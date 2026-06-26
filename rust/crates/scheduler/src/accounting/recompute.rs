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

//! Booked-counter recompute loop. Every `CONFIG.accounting.recompute_interval`:
//!
//! 1. PG side (durable, unconditional): the four existing `RECOMPUTE_*_FROM_PROC`
//!    UPDATEs in `ResourceAccountingDao::recompute_all_from_proc` are run
//!    concurrently and committed transactionally. These keep the PG accounting
//!    tables (Cuegui's view) within ~2 min of `proc` for scheduler-managed shows.
//! 2. Redis side (CAS-guarded): a single unified `SUM(proc)` snapshot
//!    keyed by (show, alloc, folder, job, layer, dept) is converted to `HSET` ops
//!    on `int_cores`/`int_gpus` fields of the five `acct:*` hashes. Sent in one
//!    `RESEED_CAS` Lua call; on CAS miss the snapshot is recomputed and retried
//!    up to `CONFIG.accounting.cas_max_retries` times. On budget exhaustion the
//!    cycle is skipped (hot-path writes are keeping Redis fresh, per §2.4).
//!
//! PG writes are independent of Redis writes - even if Redis CAS keeps missing,
//! PG converges. They are decoupled stores by design §2.1.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use futures::FutureExt;
use miette::{IntoDiagnostic, Result, WrapErr};
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::accounting::dao::{BaselineKeys, BookedSnapshotRow};
use crate::accounting::error::AccountingError;
use crate::accounting::redis_client::ReseedOp;
use crate::accounting::AccountingService;
use crate::config::CONFIG;
use crate::dao::ResourceAccountingDao;
use crate::metrics;
use crate::models::CoreSize;

pub fn spawn_loop(service: Arc<AccountingService>) {
    tokio::spawn(async move {
        let pg_dao = match ResourceAccountingDao::new().await {
            Ok(d) => Arc::new(d),
            Err(err) => {
                error!("Recompute loop aborting: PG dao init failed: {err}");
                return;
            }
        };
        let interval_dur = CONFIG.accounting.recompute_interval;
        let mut interval = time::interval(interval_dur);
        // Skip the immediate first tick - bootstrap reseed already ran at startup.
        interval.tick().await;
        // Dispatch heartbeat baseline: snapshot the session counters so the first
        // logged delta only covers events after this point.
        let mut last_dispatched = metrics::frames_dispatched_session();
        let mut last_limit_exceeded = metrics::resource_limit_exceeded_session();
        loop {
            interval.tick().await;

            // Dispatch heartbeat: the aggregate INFO that replaces the demoted
            // per-frame dispatch logs. Decoupled from the accounting reseed below.
            let current_dispatched = metrics::frames_dispatched_session();
            let dispatched_delta = current_dispatched.saturating_sub(last_dispatched);
            last_dispatched = current_dispatched;

            let current_limit_exceeded = metrics::resource_limit_exceeded_session();
            let limit_exceeded_delta = current_limit_exceeded.saturating_sub(last_limit_exceeded);
            last_limit_exceeded = current_limit_exceeded;

            info!(
                "Dispatched {} frames in the last {}ms ({} resource-limit-exceeded)",
                dispatched_delta,
                interval_dur.as_millis(),
                limit_exceeded_delta
            );

            let result = AssertUnwindSafe(async {
                if let Err(err) = run_once(&service, &pg_dao).await {
                    // The drift gauges are last-write-wins and only update on a
                    // successful reconcile, so count failures explicitly, otherwise
                    // a PG/Redis outage leaves them stuck at a stale, possibly-healthy
                    // value with no signal.
                    metrics::increment_reconcile_failure();
                    warn!("Recompute cycle failed: {err}");
                }
            })
            .catch_unwind()
            .await;
            if let Err(e) = result {
                metrics::increment_reconcile_failure();
                error!("Recompute iteration panicked: {:?}", e);
            }
        }
    });
}

/// One pass: PG recompute (unconditional) + Redis reseed (CAS-guarded).
async fn run_once(service: &AccountingService, pg_dao: &Arc<ResourceAccountingDao>) -> Result<()> {
    debug!("Recompute cycle: starting");

    // PG side: durable, scoped to scheduler-managed shows. Empty list is a no-op
    // inside the DAO so we never widen to all shows and clobber Cuebot's accounting.
    let managed_ids: Vec<uuid::Uuid> = service.managed_shows().snapshot().into_iter().collect();
    if managed_ids.is_empty() {
        debug!("PG recompute skipped: no scheduler-managed shows");
    } else {
        if let Err(err) = pg_dao.recompute_all_from_proc(&managed_ids).await {
            warn!(
                "PG recompute (layer/job/folder/point) failed (Redis reseed will still run): {err}"
            );
        }
        if let Err(err) = pg_dao.recompute_subscription_table(&managed_ids).await {
            warn!("PG subscription recompute failed (Redis reseed will still run): {err}");
        }
    }

    reconcile_redis_once(service).await
}

/// Builds the enumerable cap-key strings (sub/folder/job/point,  NOT layer) from a
/// baseline, in the same `acct:*` format as [`booked_ops_from_snapshot`]. These are
/// proc-independent, so the delta reconcile reads their current Redis values BEFORE
/// querying proc truth (residual-bias ordering, see [`reconcile_redis_once`]).
fn baseline_key_strings(baseline: &BaselineKeys) -> Vec<String> {
    let mut keys = Vec::with_capacity(
        baseline.subs.len() + baseline.folders.len() + baseline.jobs.len() + baseline.points.len(),
    );
    for (show, alloc) in &baseline.subs {
        keys.push(format!("acct:sub:{}:{}", show, alloc));
    }
    for folder in &baseline.folders {
        keys.push(format!("acct:folder:{}", folder));
    }
    for job in &baseline.jobs {
        keys.push(format!("acct:job:{}", job));
    }
    for (dept, show) in &baseline.points {
        keys.push(format!("acct:point:{}:{}", dept, show));
    }
    keys
}

/// Converts absolute target ops (from [`booked_ops_from_snapshot`]) into delta ops
/// `truth - current` against a Redis snapshot. Layer ops are dropped: nothing reads
/// the layer counter (the booking Lua checks sub/folder/job; `read_job_cores_in_use`
/// reads job), so its drift is cosmetic,  and its key is intentionally absent from
/// the pre-read `current` map. A zero delta is skipped (no-op HINCRBY).
fn delta_ops_from_targets(
    target_ops: &[ReseedOp],
    current: &HashMap<String, (i64, i64)>,
) -> Vec<ReseedOp> {
    target_ops
        .iter()
        .filter(|op| !op.key.starts_with("acct:layer:"))
        .filter_map(|op| {
            let (cur_cores, cur_gpus) = current.get(&op.key).copied().unwrap_or((0, 0));
            let cur = if op.field == "int_gpus" {
                cur_gpus
            } else {
                cur_cores
            };
            let delta = op.value - cur;
            if delta == 0 {
                None
            } else {
                Some(ReseedOp {
                    key: op.key.clone(),
                    field: op.field,
                    value: delta,
                })
            }
        })
        .collect()
}

/// Ungated delta reconcile of the booked-counter fields
///
/// Computes a per-key `truth - redis_snapshot` correction and applies it via
/// `HINCRBY` (the `RECONCILE_DELTA` Lua). Because the correction is relative, a
/// booking landing in the snapshot->apply window composes with it instead of being
/// clobbered, so no `acct:seq` CAS is needed and the reconcile can never be starved
/// by booking pressure. See the `RECONCILE_DELTA` Lua in `accounting::lua`.
///
/// Residual: PG `proc` and Redis cannot be snapshotted atomically, so the drift
/// carries one read-gap of churn. Redis is read BEFORE proc so that, under
/// increasing load, the residual biases each counter slightly HIGH (a transient,
/// self-correcting near-cap wait already absorbed by the matcher's `min(redis, proc)` gate)
/// rather than LOW (a transient over-book past a cap that would steal burst from other shows).
/// It is re-measured every cycle, so it never accumulates.
pub async fn reconcile_redis_once(service: &AccountingService) -> Result<()> {
    // 1. Enumerable cap keys (proc-independent),  read their Redis values FIRST.
    let baseline = service.dao().query_booked_baseline_keys().await?;
    let mut current = service
        .redis()
        .read_counter_fields(&baseline_key_strings(&baseline))
        .await
        .into_diagnostic()?;

    // 2. Proc truth, read AFTER Redis (residual-bias ordering above).
    let rows = service.dao().query_booked_snapshot().await?;
    let target_ops = booked_ops_from_snapshot(&rows, &baseline);

    // 3. Any non-layer target key not covered by the baseline pre-read (a proc whose
    //    sub/folder/job/point isn't enumerable,  rare) is read now so its delta is a
    //    true correction, not a blind absolute add that would double-count. NOTE: this
    //    read happens AFTER the proc snapshot, so for these (rare) keys the residual
    //    bias is inverted to slightly LOW (the over-book direction) rather than the
    //    HIGH bias the baseline keys get. Acceptable: the Lua cap stays authoritative
    //    and the drift is re-measured and corrected next cycle.
    let missing: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        target_ops
            .iter()
            .filter(|op| !op.key.starts_with("acct:layer:") && !current.contains_key(&op.key))
            .filter(|op| seen.insert(op.key.clone()))
            .map(|op| op.key.clone())
            .collect()
    };
    if !missing.is_empty() {
        let extra = service
            .redis()
            .read_counter_fields(&missing)
            .await
            .into_diagnostic()?;
        current.extend(extra);
    }

    let delta_ops = delta_ops_from_targets(&target_ops, &current);
    let n_deltas = delta_ops.len();

    // Sample the drift this cycle is erasing before applying it. NET signed core
    // drift (negative = Redis ran high, the wedge direction) is the leading
    // indicator for the incident; ABS is total magnitude; keys is the count.
    let (net_core_drift, abs_core_drift, keys_corrected) = core_drift_summary(&delta_ops);
    metrics::set_reconcile_drift(net_core_drift, abs_core_drift, keys_corrected);

    service
        .redis()
        .reconcile_delta(&delta_ops)
        .await
        .into_diagnostic()
        .wrap_err("RECONCILE_DELTA for booked counters failed")?;
    info!(
        "Delta reconcile applied: {} corrections (net_core_drift={}, abs_core_drift={}, \
         {} targets, {} rows)",
        n_deltas,
        net_core_drift,
        abs_core_drift,
        target_ops.len(),
        rows.len()
    );
    Ok(())
}

/// Summarizes the `int_cores` corrections in a delta-op batch for the reconcile
/// drift metric: `(net, abs, keys)` where `net` is the signed core-delta sum
/// (negative => Redis ran high), `abs` is the magnitude sum, and `keys` is the
/// number of counters with a non-zero core correction (one `int_cores` op per key).
fn core_drift_summary(delta_ops: &[ReseedOp]) -> (i64, i64, i64) {
    let mut net = 0i64;
    let mut abs = 0i64;
    let mut keys = 0i64;
    for op in delta_ops.iter().filter(|op| op.field == "int_cores") {
        net += op.value;
        abs += op.value.abs();
        keys += 1;
    }
    (net, abs, keys)
}

/// CAS-guarded reseed of the booked-counter fields (`int_cores`/`int_gpus`) on the
/// five `acct:*` hashes from a fresh `SUM(proc)` snapshot. Used by both the recompute
/// loop and the bootstrap. On CAS-budget exhaustion this returns
/// `AccountingError::CasContentionExceeded`: the bootstrap caller treats it as a fatal
/// startup gate, while the periodic loop downgrades it to a warn-log (per §2.4).
///
/// The snapshot is overlaid on a zero-baseline of every enumerable sub/folder/job/point
/// key (see `query_booked_baseline_keys`), so a key whose counter drifted stale-high and
/// then drained to zero procs is reset to 0 rather than being left untouched - the
/// `SUM(proc)` snapshot alone only returns keys that still have procs. Both the snapshot
/// and the baseline are re-fetched per CAS attempt, matching `limit_reseed::reseed_once`.
pub async fn reseed_redis_once(service: &AccountingService) -> Result<()> {
    let max_retries = CONFIG.accounting.cas_max_retries;
    for attempt in 0..=max_retries {
        let seq_before = service.redis().get_seq().await.into_diagnostic()?;
        let (rows, baseline) = tokio::try_join!(
            service.dao().query_booked_snapshot(),
            service.dao().query_booked_baseline_keys(),
        )?;
        let ops = booked_ops_from_snapshot(&rows, &baseline);
        debug!(
            "Recompute reseed attempt {}/{}: {} rows -> {} ops at seq={}",
            attempt + 1,
            max_retries + 1,
            rows.len(),
            ops.len(),
            seq_before
        );
        let applied = service
            .redis()
            .reseed_cas(seq_before, &ops)
            .await
            .into_diagnostic()
            .wrap_err("RESEED_CAS for booked counters failed")?;
        if applied {
            info!(
                "Recompute reseed applied: {} ops, seq={}",
                ops.len(),
                seq_before
            );
            return Ok(());
        }
        warn!(
            "Recompute reseed CAS miss (attempt {}/{}); resnapshot and retry",
            attempt + 1,
            max_retries + 1
        );
    }
    // CAS budget exhausted. Return an error so the bootstrap caller (which uses `?` as a
    // startup gate) refuses to begin booking against an unseeded Redis. The periodic
    // recompute loop catches this and downgrades it to a warn-log instead - there,
    // hot-path writes are keeping Redis fresh per design §2.4, so a skipped cycle is fine.
    Err(AccountingError::CasContentionExceeded {
        attempts: max_retries + 1,
    })
    .into_diagnostic()
}

/// Aggregate one `SUM(proc)` snapshot into HSET ops, one set of ops per unique key.
///
/// The SQL groups by `(show, alloc, folder, job, layer, dept)` - a finer granularity
/// than any of the Redis keys. A folder with several jobs, or a job whose procs span
/// multiple allocations, produces several snapshot rows that all map to the same
/// `acct:folder:{folder}` (or `acct:job:{job}`, etc.) key. Because `RESEED_CAS` does
/// `HSET` (overwrite) rather than `HINCRBY`, emitting one op per row would let later
/// rows clobber earlier ones - the final value would be whichever row sorted last,
/// not the sum across rows. Aggregate first, emit once per unique key.
///
/// `baseline` seeds a zero entry for every enumerable sub/folder/job/point key before
/// the proc sums are folded in. A key in the baseline but absent from `rows` has no
/// procs, so it emits `int_cores=0`/`int_gpus=0` - this is what lets recompute converge
/// a counter that drifted stale-high and then drained to zero procs (without it, such a
/// key would simply be missing from the snapshot and never corrected). Layers are not
/// in the baseline (no limit table to enumerate them and the booking Lua never reads the
/// layer counter), so the layer map stays purely proc-driven - residual layer drift is
/// cosmetic by design.
fn booked_ops_from_snapshot(rows: &[BookedSnapshotRow], baseline: &BaselineKeys) -> Vec<ReseedOp> {
    use std::collections::HashMap;

    let mut sub_totals: HashMap<(uuid::Uuid, uuid::Uuid), (i64, i64)> = HashMap::new();
    let mut folder_totals: HashMap<uuid::Uuid, (i64, i64)> = HashMap::new();
    let mut job_totals: HashMap<uuid::Uuid, (i64, i64)> = HashMap::new();
    let mut layer_totals: HashMap<uuid::Uuid, (i64, i64)> = HashMap::new();
    let mut point_totals: HashMap<(uuid::Uuid, uuid::Uuid), (i64, i64)> = HashMap::new();

    // Zero-baseline first: every enumerable key gets a (0, 0) entry so keys with no
    // procs still emit a resetting HSET. The proc fold below adds on top of these.
    for &k in &baseline.subs {
        sub_totals.entry(k).or_default();
    }
    for &k in &baseline.folders {
        folder_totals.entry(k).or_default();
    }
    for &k in &baseline.jobs {
        job_totals.entry(k).or_default();
    }
    for &k in &baseline.points {
        point_totals.entry(k).or_default();
    }

    for r in rows {
        let s = sub_totals.entry((r.show_id, r.alloc_id)).or_default();
        s.0 += r.cores;
        s.1 += r.gpus;
        let f = folder_totals.entry(r.folder_id).or_default();
        f.0 += r.cores;
        f.1 += r.gpus;
        let j = job_totals.entry(r.job_id).or_default();
        j.0 += r.cores;
        j.1 += r.gpus;
        let l = layer_totals.entry(r.layer_id).or_default();
        l.0 += r.cores;
        l.1 += r.gpus;
        let p = point_totals.entry((r.dept_id, r.show_id)).or_default();
        p.0 += r.cores;
        p.1 += r.gpus;
    }

    let total_keys = sub_totals.len()
        + folder_totals.len()
        + job_totals.len()
        + layer_totals.len()
        + point_totals.len();
    let mut ops = Vec::with_capacity(total_keys * 2);

    fn push_pair(ops: &mut Vec<ReseedOp>, key: String, cores_centi: i64, gpus: i64) {
        // PG centicores → Redis cores via the typed conversion. Booked sums are
        // non-negative, so the non-cap variant is correct here.
        ops.push(ReseedOp {
            key: key.clone(),
            field: "int_cores",
            value: i64::from(CoreSize::from_multiplied(cores_centi).value()),
        });
        ops.push(ReseedOp {
            key,
            field: "int_gpus",
            value: gpus,
        });
    }

    for ((show_id, alloc_id), (cores, gpus)) in sub_totals {
        push_pair(
            &mut ops,
            format!("acct:sub:{}:{}", show_id, alloc_id),
            cores,
            gpus,
        );
    }
    for (folder_id, (cores, gpus)) in folder_totals {
        push_pair(&mut ops, format!("acct:folder:{}", folder_id), cores, gpus);
    }
    for (job_id, (cores, gpus)) in job_totals {
        push_pair(&mut ops, format!("acct:job:{}", job_id), cores, gpus);
    }
    for (layer_id, (cores, gpus)) in layer_totals {
        push_pair(&mut ops, format!("acct:layer:{}", layer_id), cores, gpus);
    }
    for ((dept_id, show_id), (cores, gpus)) in point_totals {
        push_pair(
            &mut ops,
            format!("acct:point:{}:{}", dept_id, show_id),
            cores,
            gpus,
        );
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn job_op(key: &str, field: &'static str, value: i64) -> ReseedOp {
        ReseedOp {
            key: key.to_string(),
            field,
            value,
        }
    }

    /// The wedge-correcting case: proc truth is low, Redis drifted high. The delta
    /// must be negative and pull the counter back down to truth.
    #[test]
    fn delta_ops_correct_upward_drift_with_negative_delta() {
        let key = format!("acct:job:{}", Uuid::new_v4());
        // truth = 10 cores, Redis drifted to 500 (the incident scenario).
        let targets = vec![job_op(&key, "int_cores", 10)];
        let mut current = HashMap::new();
        current.insert(key.clone(), (500, 0));

        let deltas = delta_ops_from_targets(&targets, &current);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].value, -490); // 500 + (-490) = 10
    }

    /// truth - current for each field independently; a zero delta is dropped.
    #[test]
    fn delta_ops_per_field_and_skip_zero() {
        let key = format!("acct:job:{}", Uuid::new_v4());
        let targets = vec![job_op(&key, "int_cores", 40), job_op(&key, "int_gpus", 2)];
        let mut current = HashMap::new();
        current.insert(key.clone(), (25, 2)); // cores low by 15, gpus exact

        let deltas = delta_ops_from_targets(&targets, &current);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].field, "int_cores");
        assert_eq!(deltas[0].value, 15);
    }

    /// Layer ops are never reconciled (cosmetic counter, absent from the pre-read).
    #[test]
    fn delta_ops_drop_layer_keys() {
        let key = format!("acct:layer:{}", Uuid::new_v4());
        let targets = vec![job_op(&key, "int_cores", 99)];
        let deltas = delta_ops_from_targets(&targets, &HashMap::new());
        assert!(deltas.is_empty());
    }

    /// A non-layer key absent from the pre-read map is treated as current=0, so the
    /// delta equals the target. (`reconcile_redis_once` guarantees such keys are
    /// re-read before this runs, but the floor must be correct regardless.)
    #[test]
    fn delta_ops_absent_current_treated_as_zero() {
        let key = format!("acct:job:{}", Uuid::new_v4());
        let targets = vec![job_op(&key, "int_cores", 7)];
        let deltas = delta_ops_from_targets(&targets, &HashMap::new());
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].value, 7);
    }

    /// Drift summary nets signed core deltas, sums magnitudes, counts core keys,
    /// and ignores gpu ops.
    #[test]
    fn core_drift_summary_nets_and_magnitudes_cores_only() {
        let job = format!("acct:job:{}", Uuid::new_v4());
        let sub = format!("acct:sub:{}:{}", Uuid::new_v4(), Uuid::new_v4());
        let ops = vec![
            job_op(&job, "int_cores", -490), // Redis ran high (wedge direction)
            job_op(&job, "int_gpus", 3),     // ignored: not a core correction
            job_op(&sub, "int_cores", 12),   // Redis ran low
        ];
        let (net, abs, keys) = core_drift_summary(&ops);
        assert_eq!(net, -478); // -490 + 12
        assert_eq!(abs, 502); //  490 + 12
        assert_eq!(keys, 2);
    }

    #[test]
    fn baseline_key_strings_match_publisher_format_and_exclude_layers() {
        let show = Uuid::new_v4();
        let alloc = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let job = Uuid::new_v4();
        let dept = Uuid::new_v4();
        let baseline = BaselineKeys {
            subs: vec![(show, alloc)],
            folders: vec![folder],
            jobs: vec![job],
            points: vec![(dept, show)],
        };

        let keys = baseline_key_strings(&baseline);
        assert_eq!(keys.len(), 4);
        assert!(keys.contains(&format!("acct:sub:{}:{}", show, alloc)));
        assert!(keys.contains(&format!("acct:folder:{}", folder)));
        assert!(keys.contains(&format!("acct:job:{}", job)));
        assert!(keys.contains(&format!("acct:point:{}:{}", dept, show)));
        assert!(!keys.iter().any(|k| k.starts_with("acct:layer:")));
    }

    fn fixture_row() -> BookedSnapshotRow {
        // PG-shaped: `cores` is centicores per SUM(proc.int_cores_reserved). 4200 = 42 cores.
        BookedSnapshotRow {
            show_id: Uuid::nil(),
            alloc_id: Uuid::nil(),
            folder_id: Uuid::nil(),
            job_id: Uuid::nil(),
            layer_id: Uuid::nil(),
            dept_id: Uuid::nil(),
            cores: 4200,
            gpus: 3,
        }
    }

    fn find_op<'a>(ops: &'a [ReseedOp], key: &str, field: &str) -> &'a ReseedOp {
        ops.iter()
            .find(|o| o.key == key && o.field == field)
            .unwrap_or_else(|| panic!("no op for key={key} field={field}"))
    }

    fn count_ops_for_key(ops: &[ReseedOp], key: &str) -> usize {
        ops.iter().filter(|o| o.key == key).count()
    }

    fn empty_baseline() -> BaselineKeys {
        BaselineKeys::default()
    }

    #[test]
    fn snapshot_single_row_expands_to_ten_ops_in_cores() {
        let ops = booked_ops_from_snapshot(&[fixture_row()], &empty_baseline());
        // 5 unique keys × 2 fields (int_cores, int_gpus).
        assert_eq!(ops.len(), 10);
        let cores_ops: Vec<_> = ops.iter().filter(|o| o.field == "int_cores").collect();
        let gpus_ops: Vec<_> = ops.iter().filter(|o| o.field == "int_gpus").collect();
        assert_eq!(cores_ops.len(), 5);
        assert_eq!(gpus_ops.len(), 5);
        // PG centicores 4200 -> Redis cores 42.
        assert!(cores_ops.iter().all(|o| o.value == 42));
        // GPUs pass through unconverted.
        assert!(gpus_ops.iter().all(|o| o.value == 3));
    }

    #[test]
    fn snapshot_keys_match_publisher_format() {
        let ops = booked_ops_from_snapshot(&[fixture_row()], &empty_baseline());
        let keys: std::collections::HashSet<&str> = ops.iter().map(|o| o.key.as_str()).collect();
        assert!(keys.contains(
            "acct:sub:00000000-0000-0000-0000-000000000000:00000000-0000-0000-0000-000000000000"
        ));
        assert!(keys.contains("acct:folder:00000000-0000-0000-0000-000000000000"));
        assert!(keys.contains("acct:job:00000000-0000-0000-0000-000000000000"));
        assert!(keys.contains("acct:layer:00000000-0000-0000-0000-000000000000"));
        assert!(keys.contains(
            "acct:point:00000000-0000-0000-0000-000000000000:00000000-0000-0000-0000-000000000000"
        ));
    }

    /// Two jobs in the same folder, same sub, same point. The coarse counters must
    /// SUM across the per-job snapshot rows, not pick "last write wins."
    /// Snapshot `cores` are PG centicores; assertions are in Redis cores.
    #[test]
    fn snapshot_sums_coarse_keys_across_per_job_rows() {
        let show = Uuid::new_v4();
        let alloc = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let dept = Uuid::new_v4();
        let row_a = BookedSnapshotRow {
            show_id: show,
            alloc_id: alloc,
            folder_id: folder,
            job_id: Uuid::new_v4(),
            layer_id: Uuid::new_v4(),
            dept_id: dept,
            cores: 1000, // 10 cores
            gpus: 1,
        };
        let row_b = BookedSnapshotRow {
            show_id: show,
            alloc_id: alloc,
            folder_id: folder,
            job_id: Uuid::new_v4(),
            layer_id: Uuid::new_v4(),
            dept_id: dept,
            cores: 2500, // 25 cores
            gpus: 2,
        };

        let ops = booked_ops_from_snapshot(&[row_a, row_b], &empty_baseline());

        // Centicores summed (3500), then /100 -> 35 cores.
        let sub_key = format!("acct:sub:{}:{}", show, alloc);
        assert_eq!(find_op(&ops, &sub_key, "int_cores").value, 35);
        assert_eq!(find_op(&ops, &sub_key, "int_gpus").value, 3);
        assert_eq!(count_ops_for_key(&ops, &sub_key), 2);

        let folder_key = format!("acct:folder:{}", folder);
        assert_eq!(find_op(&ops, &folder_key, "int_cores").value, 35);
        assert_eq!(find_op(&ops, &folder_key, "int_gpus").value, 3);
        assert_eq!(count_ops_for_key(&ops, &folder_key), 2);

        let point_key = format!("acct:point:{}:{}", dept, show);
        assert_eq!(find_op(&ops, &point_key, "int_cores").value, 35);
        assert_eq!(find_op(&ops, &point_key, "int_gpus").value, 3);
        assert_eq!(count_ops_for_key(&ops, &point_key), 2);
    }

    /// One job whose procs span two allocations. The job and layer counters must sum
    /// across the two snapshot rows, while the two sub counters are independent.
    /// Snapshot `cores` are PG centicores; assertions are in Redis cores.
    #[test]
    fn snapshot_sums_job_and_layer_across_allocations() {
        let show = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let dept = Uuid::new_v4();
        let job = Uuid::new_v4();
        let layer = Uuid::new_v4();
        let alloc_a = Uuid::new_v4();
        let alloc_b = Uuid::new_v4();
        let rows = [
            BookedSnapshotRow {
                show_id: show,
                alloc_id: alloc_a,
                folder_id: folder,
                job_id: job,
                layer_id: layer,
                dept_id: dept,
                cores: 1000, // 10 cores
                gpus: 0,
            },
            BookedSnapshotRow {
                show_id: show,
                alloc_id: alloc_b,
                folder_id: folder,
                job_id: job,
                layer_id: layer,
                dept_id: dept,
                cores: 700, // 7 cores
                gpus: 0,
            },
        ];

        let ops = booked_ops_from_snapshot(&rows, &empty_baseline());

        let job_key = format!("acct:job:{}", job);
        assert_eq!(find_op(&ops, &job_key, "int_cores").value, 17);
        assert_eq!(count_ops_for_key(&ops, &job_key), 2);

        let layer_key = format!("acct:layer:{}", layer);
        assert_eq!(find_op(&ops, &layer_key, "int_cores").value, 17);
        assert_eq!(count_ops_for_key(&ops, &layer_key), 2);

        // Sub counters stay per-allocation.
        let sub_a = format!("acct:sub:{}:{}", show, alloc_a);
        let sub_b = format!("acct:sub:{}:{}", show, alloc_b);
        assert_eq!(find_op(&ops, &sub_a, "int_cores").value, 10);
        assert_eq!(find_op(&ops, &sub_b, "int_cores").value, 7);
    }

    /// A baseline key with no matching proc row (its procs drained to zero) must emit a
    /// resetting `int_cores=0`/`int_gpus=0` pair so recompute can converge a stale-high
    /// counter back to truth. This is the core of the zero-convergence fix.
    #[test]
    fn baseline_key_absent_from_snapshot_emits_zero_pair() {
        let show = Uuid::new_v4();
        let alloc = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let job = Uuid::new_v4();
        let dept = Uuid::new_v4();
        let baseline = BaselineKeys {
            subs: vec![(show, alloc)],
            folders: vec![folder],
            jobs: vec![job],
            points: vec![(dept, show)],
        };

        // No proc rows at all: every baseline key drained to zero.
        let ops = booked_ops_from_snapshot(&[], &baseline);

        // 4 enumerable keys × 2 fields; layers have no baseline so none appear.
        assert_eq!(ops.len(), 8);
        for key in [
            format!("acct:sub:{}:{}", show, alloc),
            format!("acct:folder:{}", folder),
            format!("acct:job:{}", job),
            format!("acct:point:{}:{}", dept, show),
        ] {
            assert_eq!(find_op(&ops, &key, "int_cores").value, 0);
            assert_eq!(find_op(&ops, &key, "int_gpus").value, 0);
        }
    }

    /// A baseline key that also appears in the snapshot is not double-counted: it emits
    /// one pair carrying the proc sum, not the seeded zero plus the sum.
    #[test]
    fn baseline_key_present_in_snapshot_uses_proc_sum_once() {
        let row = fixture_row(); // all-nil keys, 4200 centicores -> 42 cores, 3 gpus.
        let baseline = BaselineKeys {
            subs: vec![(Uuid::nil(), Uuid::nil())],
            folders: vec![Uuid::nil()],
            jobs: vec![Uuid::nil()],
            points: vec![(Uuid::nil(), Uuid::nil())],
        };

        let ops = booked_ops_from_snapshot(&[row], &baseline);

        // Still one pair per key (no zero/sum duplication): 5 keys × 2 fields.
        assert_eq!(ops.len(), 10);
        let job_key = "acct:job:00000000-0000-0000-0000-000000000000";
        assert_eq!(count_ops_for_key(&ops, job_key), 2);
        assert_eq!(find_op(&ops, job_key, "int_cores").value, 42);
        assert_eq!(find_op(&ops, job_key, "int_gpus").value, 3);
    }

    /// Mixed: one baseline job has procs (keep its sum), another drained to zero (reset).
    /// The layer that exists only in the snapshot is still emitted from proc data.
    #[test]
    fn baseline_resets_drained_key_while_keeping_active_one() {
        let show = Uuid::new_v4();
        let alloc = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let dept = Uuid::new_v4();
        let active_job = Uuid::new_v4();
        let drained_job = Uuid::new_v4();
        let active_layer = Uuid::new_v4();

        let baseline = BaselineKeys {
            subs: vec![(show, alloc)],
            folders: vec![folder],
            jobs: vec![active_job, drained_job],
            points: vec![(dept, show)],
        };
        let rows = [BookedSnapshotRow {
            show_id: show,
            alloc_id: alloc,
            folder_id: folder,
            job_id: active_job,
            layer_id: active_layer,
            dept_id: dept,
            cores: 500, // 5 cores
            gpus: 1,
        }];

        let ops = booked_ops_from_snapshot(&rows, &baseline);

        let active_key = format!("acct:job:{}", active_job);
        assert_eq!(find_op(&ops, &active_key, "int_cores").value, 5);
        assert_eq!(find_op(&ops, &active_key, "int_gpus").value, 1);

        let drained_key = format!("acct:job:{}", drained_job);
        assert_eq!(find_op(&ops, &drained_key, "int_cores").value, 0);
        assert_eq!(find_op(&ops, &drained_key, "int_gpus").value, 0);

        // Layer is proc-driven only; the active layer is present, no zero-baseline layers.
        let layer_key = format!("acct:layer:{}", active_layer);
        assert_eq!(find_op(&ops, &layer_key, "int_cores").value, 5);
        assert_eq!(
            ops.iter()
                .filter(|o| o.key.starts_with("acct:layer:"))
                .count(),
            2
        );
    }
}
