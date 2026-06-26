// Copyright Contributors to the OpenCue Project
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

// TODO: per-booking idempotency token if duplicate-booking rate becomes material (design §5).

/// Hot-path booking script. KEYS / ARGV layout:
///
/// ```text
/// KEYS[1] = acct:sub:{show_id}:{alloc_id}
/// KEYS[2] = acct:folder:{folder_id}
/// KEYS[3] = acct:job:{job_id}
/// KEYS[4] = acct:layer:{layer_id}
/// KEYS[5] = acct:point:{dept_id}:{show_id}
/// KEYS[6] = acct:seq
/// ARGV[1] = core_delta  (signed int as string)
/// ARGV[2] = gpu_delta   (signed int as string)
/// ARGV[3] = force       ("0" to enforce limits, "1" to bypass)
/// ```
///
/// Return shape:
/// - `{1, new_seq}`                              on success
/// - `{0, table_name, current_value, limit}`     on limit-exceeded (force=0 only)
///
/// Cap semantics:
/// - **Subscription burst** is enforced unconditionally. `int_burst=0` means
///   "reject all bookings", matching Cuebot's `s.int_cores + ? > s.int_burst`
///   check in `SubscriptionDaoJdbc.IS_SHOW_OVER_BURST`. The bootstrap reseed
///   populates burst before the scheduler accepts work, so unconfigured
///   subscriptions cannot dispatch.
/// - **Folder / job `int_max_cores` / `int_max_gpus`** retain the `> 0` guard.
///   Cuebot's convention uses `-1` (the schema default for `folder_resource.
///   int_max_cores` and `int_max_gpus`) as the "unlimited" sentinel, and 0 is
///   not a meaningful configured value for these caps in practice. Core caps
///   are checked only when `core_delta > 0`; GPU caps only when `gpu_delta > 0`.
///   Mirrors `DispatchQuery.FIND_JOBS_BY_SHOW_PRIORITY_MODE`'s
///   `job_resource.int_gpus + layer.int_gpus_min < job_resource.int_max_gpus`
///   predicate that lived in PG before accounting moved to Redis.
///
/// Units: every numeric field this script reads and writes - `int_cores`, `size`,
/// `burst`, `int_max_cores` - is in **cores** (not centicores). Conversion from PG's
/// centicore storage happens at the limit-reseed and booked-counter-recompute
/// boundaries; the Cuebot release publisher and the Rust booking-delta builder
/// likewise pass cores into this script. See design §0 unit invariant.
pub const BOOK_OR_FORCE: &str = r#"
local core_d = tonumber(ARGV[1])
local gpu_d  = tonumber(ARGV[2])
local force  = ARGV[3] == "1"

if not force then
  if core_d > 0 then
    local cur_sub   = tonumber(redis.call('HGET', KEYS[1], 'int_cores') or "0")
    local sub_burst = tonumber(redis.call('HGET', KEYS[1], 'burst')     or "0")
    if (cur_sub + core_d) > sub_burst then
      return {0, "subscription", cur_sub, sub_burst}
    end

    local cur_folder = tonumber(redis.call('HGET', KEYS[2], 'int_cores')     or "0")
    local folder_max = tonumber(redis.call('HGET', KEYS[2], 'int_max_cores') or "0")
    if folder_max > 0 and (cur_folder + core_d) > folder_max then
      return {0, "folder", cur_folder, folder_max}
    end

    local cur_job = tonumber(redis.call('HGET', KEYS[3], 'int_cores')     or "0")
    local job_max = tonumber(redis.call('HGET', KEYS[3], 'int_max_cores') or "0")
    if job_max > 0 and (cur_job + core_d) > job_max then
      return {0, "job", cur_job, job_max}
    end
  end

  if gpu_d > 0 then
    local cur_folder_gpu = tonumber(redis.call('HGET', KEYS[2], 'int_gpus')     or "0")
    local folder_gpu_max = tonumber(redis.call('HGET', KEYS[2], 'int_max_gpus') or "0")
    if folder_gpu_max > 0 and (cur_folder_gpu + gpu_d) > folder_gpu_max then
      return {0, "folder_gpus", cur_folder_gpu, folder_gpu_max}
    end

    local cur_job_gpu = tonumber(redis.call('HGET', KEYS[3], 'int_gpus')     or "0")
    local job_gpu_max = tonumber(redis.call('HGET', KEYS[3], 'int_max_gpus') or "0")
    if job_gpu_max > 0 and (cur_job_gpu + gpu_d) > job_gpu_max then
      return {0, "job_gpus", cur_job_gpu, job_gpu_max}
    end
  end
end

redis.call('HINCRBY', KEYS[1], 'int_cores', core_d)
redis.call('HINCRBY', KEYS[1], 'int_gpus',  gpu_d)
redis.call('HINCRBY', KEYS[2], 'int_cores', core_d)
redis.call('HINCRBY', KEYS[2], 'int_gpus',  gpu_d)
redis.call('HINCRBY', KEYS[3], 'int_cores', core_d)
redis.call('HINCRBY', KEYS[3], 'int_gpus',  gpu_d)
redis.call('HINCRBY', KEYS[4], 'int_cores', core_d)
redis.call('HINCRBY', KEYS[4], 'int_gpus',  gpu_d)
redis.call('HINCRBY', KEYS[5], 'int_cores', core_d)
redis.call('HINCRBY', KEYS[5], 'int_gpus',  gpu_d)
-- `acct:seq` is bumped on every mutation, including force-mode rollbacks (design
-- §2.4 - all mutations bump seq so concurrent reseed CAS attempts notice). Trade-off:
-- during a wave of force-rollbacks (e.g. flaky RQD launch failures) the reseed CAS
-- budget can be exhausted, causing the recompute cycle to skip. Acceptable per
-- design - hot-path writes are keeping Redis fresh; recompute is reconciliation,
-- not primary sync.
return {1, redis.call('INCR', KEYS[6])}
"#;

/// Reseed write under the `acct:seq` CAS guard. Used by both the recompute loop
/// and the limit reseed loop. ARGV-encoded ops (rather than KEYS) because Redis
/// Cluster is out of scope (single-node per design §2.4) and ARGV avoids the
/// 8000-key EVALSHA limit when reseeding thousands of shows in one shot.
///
/// ```text
/// KEYS[1] = acct:seq
/// ARGV[1] = seq_before (string-encoded i64)
/// ARGV[2] = n_ops      (string-encoded i64)
/// For i in 1..=n_ops:
///   ARGV[2 + 3*(i-1) + 1] = key
///   ARGV[2 + 3*(i-1) + 2] = field
///   ARGV[2 + 3*(i-1) + 3] = value
/// ```
///
/// Returns `1` on success, `0` on CAS miss (caller recomputes snapshot and retries).
/// Does NOT bump `acct:seq` - reseed is reconciliation, not mutation; bumping would
/// invalidate any concurrent CAS attempts.
pub const RESEED_CAS: &str = r#"
local cur = redis.call('GET', KEYS[1]) or "0"
if cur ~= ARGV[1] then return 0 end

local n = tonumber(ARGV[2])
for i = 0, n - 1 do
  local base = 3 + i * 3
  redis.call('HSET', ARGV[base], ARGV[base + 1], ARGV[base + 2])
end
return 1
"#;

/// Nudges each booked counter back toward its true value (from `SUM(proc)`) by
/// *adding* a small correction, rather than overwriting it. The caller passes a
/// per-key `delta = truth - redis`, computed from a snapshot it took a moment ago,
/// and this script applies it with `HINCRBY`.
///
/// Why add instead of overwrite (`HSET`)? A frame booking happening at the same
/// instant is also an `HINCRBY` on the same counter, so the booking and the
/// correction simply add together,  neither is lost. An `HSET` overwrite would
/// erase a booking that landed after the snapshot, which is exactly why the old
/// absolute reseed (`RESEED_CAS`) needed an `acct:seq` lock to exclude concurrent
/// bookings. That lock was the bug: under booking load `acct:seq` changed faster
/// than the reseed could win it, so whole reconcile cycles were skipped and the
/// counters drifted unbounded. Because adding is safe with concurrent bookings,
/// this script needs no lock and always runs.
///
/// Worked example,  counter is drifted high at 50, the truth is 10 (delta -40):
///   - snapshot reads redis = 50, so delta = 10 - 50 = -40
///   - a +10 booking lands first:            50 -> 60
///   - this script applies the -40:          60 -> 20
///   - result 20 = truth(10) + booking(10)   ✓ drift fixed, booking kept
///
/// Other details:
///   - Does NOT bump `acct:seq` (it's reconciliation, not a booking), so it never
///     disturbs the bootstrap `RESEED_CAS`.
///   - Floors each field at 0: a correction that overshoots must never leave a
///     negative counter, which the booking Lua would misread as unlimited headroom.
///
/// Args (ARGV-only, like `RESEED_CAS`, to dodge the EVALSHA key-count ceiling when
/// correcting thousands of counters at once; single-node Redis per design §2.4):
/// ```text
/// ARGV[1] = n_ops
/// For each op i in 0..n_ops-1:
///   ARGV[1 + 3*i + 1] = key
///   ARGV[1 + 3*i + 2] = field
///   ARGV[1 + 3*i + 3] = delta   (truth - redis_snapshot)
/// ```
pub const RECONCILE_DELTA: &str = r#"
local n = tonumber(ARGV[1])
for i = 0, n - 1 do
  local base = 1 + i * 3
  local key   = ARGV[base + 1]
  local field = ARGV[base + 2]
  local delta = tonumber(ARGV[base + 3])
  if delta ~= 0 then
    local v = redis.call('HINCRBY', key, field, delta)
    if v < 0 then
      redis.call('HSET', key, field, 0)
    end
  end
end
return n
"#;
