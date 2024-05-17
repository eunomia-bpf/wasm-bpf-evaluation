from typing import Union
import pathlib
import os
from typing import List
from subprocess import Popen, PIPE
import signal
WORK_DIR = pathlib.Path(__file__).parent

ASSETS_DIR = WORK_DIR/"assets"

WASM_BPF = WORK_DIR.parent/"assets"/"wasm-bpf"

DOCKER_IMAGE = "5a03a529e80b"
FLAME_GRAPH_ROOT = pathlib.Path("/root/FlameGraph")


def run_simple(cmdline: List[str], perf_data_name: Union[str, None] = None, start_victim: bool = False):
    victim_pid = None
    if start_victim:
        victim = Popen([ASSETS_DIR/"target"], cwd=ASSETS_DIR,
                       stdout=PIPE, stdin=PIPE)
        victim_pid = victim.pid
    if perf_data_name:
        cmdline = ["perf_6.2", "record", "-g",
                   "-o", str(perf_data_name)+".perf_data",  "--", *cmdline]
    print(cmdline)
    proc = Popen(cmdline, text=True, stdout=PIPE, cwd=ASSETS_DIR)

    lines = proc.stdout.readlines()
    if perf_data_name:
        os.system(
            f"perf_6.2 script -i {str(perf_data_name)+'.perf_data'} > {perf_data_name}")
        os.remove(str(perf_data_name)+".perf_data")
        os.system(f"{FLAME_GRAPH_ROOT/'stackcollapse-perf.pl'} < {str(perf_data_name)} | {FLAME_GRAPH_ROOT/'flamegraph.pl'} > {str(perf_data_name)+'.svg'}")
    if start_victim:
        victim.send_signal(signal.SIGINT)
        victim.wait()
    print(lines)
    data_line = lines[-1]
    time, count = (float(x) for x in data_line.strip().split())
    return time/count


def generate_statistics(data: List[float]):
    sqrsum = sum(x**2 for x in data)
    avg = sum(data)/len(data)
    sqr = sqrsum/len(data) - avg**2
    return {
        "max": max(data),
        "min": min(data),
        "sqr": sqr,
        "avg": avg,
        "count": len(data),
        "raw_data": data
    }


def main():
    if not os.path.exists(WORK_DIR/"result"):
        os.mkdir(WORK_DIR/"result")
    if not os.path.exists(ASSETS_DIR):
        os.mkdir(ASSETS_DIR)
        os.system(
            f"cd {WORK_DIR/'map_benchmark'} && make clean && make -j && cp map_benchmark.wasm {ASSETS_DIR}")
        os.system(
            f"cd {WORK_DIR/'map_benchmark'} && make clean && make -f Makefile.native clean && make -f Makefile.native -j && cp map_benchmark {ASSETS_DIR}")
    native_result_with_perf = []
    native_result_without_perf = []

    for i in range(10):
        native_result_with_perf.append(run_simple(
            [str(ASSETS_DIR/"map_benchmark")], WORK_DIR/"result"/f"native{i}.perf", False))
        native_result_without_perf.append(run_simple(
            [str(ASSETS_DIR/"map_benchmark")]))
    wasm_result_with_perf = []
    wasm_result_without_perf = []
    for i in range(10):
        wasm_result_with_perf.append(run_simple(
            [WASM_BPF, str(ASSETS_DIR/"map_benchmark.wasm")], WORK_DIR/"result"/f"wasm{i}.perf"))
        wasm_result_without_perf.append(run_simple(
            [WASM_BPF, str(ASSETS_DIR/"map_benchmark.wasm")], None))
    docker_result = []
    for i in range(10):
        docker_result.append(
            run_simple(["docker", "run", "--privileged", "-v", "/sys:/sys", DOCKER_IMAGE], None))
    result = {
        "native_perf": generate_statistics(native_result_with_perf),
        "native_no_perf": generate_statistics(native_result_without_perf),
        "wasm_perf": generate_statistics(wasm_result_with_perf),
        "wasm_no_perf": generate_statistics(wasm_result_without_perf),
        "docker": generate_statistics(docker_result)
    }
    print(result)
    import json
    with open("result.json", "w") as f:
        json.dump(result, f)


if __name__ == "__main__":
    main()
