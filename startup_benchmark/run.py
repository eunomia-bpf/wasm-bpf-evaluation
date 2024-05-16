import pathlib
import shutil
import os
import subprocess
import time
import signal
from typing import List
WORK_DIR = pathlib.Path(__file__).parent
PROJECT_ROOT = WORK_DIR.parent
RUN_COUNT = 10
DOCKER_IMAGE = "6203a9d12082"


def run_simple_process(cmd: List[str]):
    proc = subprocess.Popen(
        cmd, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False,)
    now = time.time()
    while proc.stdout:
        line = proc.stdout.readline()
        if line.startswith(b"Attach ok!"):
            break
    t = time.time()
    assert line.startswith(b"Attach ok!")
    print(line, t-now)
    proc.send_signal(signal.SIGTERM)
    proc.wait()
    return t - now


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


def run_startup_test():
    if not os.path.exists(WORK_DIR/"assets"):
        os.mkdir(WORK_DIR/"assets")
        bootstrap_root = PROJECT_ROOT/"examples"/"bootstrap"
        os.system(f"cd {bootstrap_root} && make clean && make -j")
        shutil.copy(bootstrap_root/"bootstrap.wasm", WORK_DIR/"assets")
        os.system(f"cd {bootstrap_root} && make clean")
        print("botostrap-wasm compiled")
        os.system(
            f"cd {bootstrap_root} && make -f Makefile.native clean && make -f Makefile.native -j")
        shutil.copy(bootstrap_root/"bootstrap", WORK_DIR/"assets")
        print("bootstrap native compiled")
    docker_result = []
    for _ in range(100):
        curr = run_simple_process([
            "docker", "run", "--rm", "--privileged", "-v", "/sys:/sys", DOCKER_IMAGE
        ])
        docker_result.append(curr)
    native_data = []
    for _ in range(100):
        curr = run_simple_process([str(WORK_DIR/"assets"/"bootstrap")])
        native_data.append(curr)
    wasm_bpf_data = []
    for _ in range(100):
        curr = run_simple_process(
            [str(PROJECT_ROOT/"assets"/"wasm-bpf"), str(WORK_DIR/"assets"/"bootstrap.wasm")])
        wasm_bpf_data.append(curr)

    result = {
        "native": generate_statistics(native_data),
        "wasm": generate_statistics(wasm_bpf_data),
        "docker": generate_statistics(docker_result)
    }
    print(result)
    import json
    with open(WORK_DIR/"startup.json", "w") as f:
        json.dump(result, f)


def main():
    run_startup_test()


if __name__ == "__main__":
    main()
