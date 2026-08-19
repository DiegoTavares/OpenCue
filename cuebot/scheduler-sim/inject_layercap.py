"""LAYERCAP workload: one deep single-layer flood of 1-core frames.

The pathological shape from production: one layer with thousands of identical
1-core frames and a huge maxcores, on a farm with room to blanket whole
machines. With the per-host layer cap off, the locality bonus piles the layer
onto one host until it is full; with the cap on, the flood must spill across
hosts. layercap_watch.py measures which happened.

One job, one layer, submitted once. No top-up: a second job would be a second
layer and dilute the premise.

usage: inject_layercap.py [duration_s]
"""
import os, sys, time
import grpc
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "opencue_proto"))
sys.path.insert(0, _HERE)
import job_pb2, job_pb2_grpc
import sim_model
import farm_spec as spec

CUEBOT = spec.GRPC
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 180
FRAMES = int(os.environ.get("SIM_LAYERCAP_FRAMES", "20000"))
TOKEN = "simlayercap"

SPEC_HEAD = ('<?xml version="1.0"?>\n'
  '<!DOCTYPE spec SYSTEM "http://localhost:8080/spcue/dtd/cjsl-1.15.dtd">\n'
  '<spec>\n  <facility>sim</facility>\n  <show>sim</show>\n  <shot>test</shot>\n'
  '  <user>sim</user>\n  <uid>9860</uid>\n')


def make_job():
    layer = (f'      <layer name="flood" type="Render"><cmd>/bin/true</cmd>'
             f'<range>1-{FRAMES}</range><chunk>1</chunk>'
             f'<cores>{sim_model.CORE_POINTS}</cores>'
             f'<threadable>0</threadable><memory>512mb</memory>'
             f'<tags>{spec.TAG}</tags>'
             f'<services><service>shell</service></services></layer>')
    return (f'  <job name="sim-test-{TOKEN}-00001"><paused>false</paused>'
            f'<priority>100</priority><maxcores>80000</maxcores>\n'
            f'    <layers>\n{layer}\n    </layers>\n  </job>\n')


def main():
    chan = grpc.insecure_channel(CUEBOT)
    grpc.channel_ready_future(chan).result(timeout=15)
    stub = job_pb2_grpc.JobInterfaceStub(chan)
    xml = SPEC_HEAD + make_job() + "</spec>\n"
    stub.LaunchSpec(job_pb2.JobLaunchSpecRequest(spec=xml))
    print(f"LAYERCAP flood: one layer, {FRAMES} 1-core frames, staying up "
          f"{DURATION}s.", flush=True)
    t0 = time.time()
    while time.time() - t0 < DURATION:
        time.sleep(5)
    print("injector done", flush=True)


if __name__ == "__main__":
    main()
