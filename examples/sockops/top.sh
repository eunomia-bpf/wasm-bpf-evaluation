#!/bin/bash
set -e  # 在发生错误时退出脚本
set -x  # 显示每个命令在执行前的详细信息

# 定义清理函数，以便在脚本退出时终止后台进程
cleanup() {
    echo "Cleaning up..."
    kill -9 "$pid" 2>/dev/null || true
    kill -9 "$pid2" 2>/dev/null || true
    exit
}

# 捕获 SIGINT 和 SIGTERM 信号，调用 cleanup 函数
trap cleanup SIGINT SIGTERM

# 获取脚本的初始目录
initial_dir=$(pwd)

# 启动 wasm-bpf 并将输出重定向到 bootstrap.txt
echo "Starting wasm-bpf..."
sudo ../../../wasm-bpf/wasm-bpf ./sockops.wasm > "$initial_dir/sockops.txt" 2>&1 &
pid=$!
echo "wasm-bpf started with PID $pid"

# 切换到 solana 目录
echo "Changing directory to ~/..."
cd ~/ || { echo "Failed to change directory to ~/"; cleanup; }

# 执行 cargo clean

# 启动 cargo build 并将输出重定向到 cargo_build.txt
echo "Starting cargo build..."
iperf3 -c 127.0.0.1 -t 10 -l 64k -p 10000 > "$initial_dir/sockops.txt" 2>&1 &
pid2=$!
echo "cargo build started with PID $pid2"

# 检查 cargo build 是否成功启动
if ! ps -p "$pid2" > /dev/null; then
    echo "cargo build did not start correctly."
    cleanup
fi

# 切换回初始目录
cd "$initial_dir" || { echo "Failed to change back to initial directory"; cleanup; }

# 初始化 top.txt 并写入表头
# echo "%CPU %MEM CMD" > ./top.txt
# echo "Initialized top.txt with header."

# 监控 cargo build 的 CPU 和内存使用，直到进程结束
echo "Monitoring cargo build (PID $pid2)..."
while ps -p "$pid2" > /dev/null; do
    ps -p "$pid2" -o %cpu,%mem,cmd >> ./top.txt
    ps -p "$pid" -o %cpu,%mem,cmd >> ./top1.txt
    sleep 0.1
done

echo "cargo build (PID $pid2) has finished."

# 终止 wasm-bpf 进程
echo "Killing wasm-bpf (PID $pid)..."
kill -9 "$pid"
echo "wasm-bpf (PID $pid) killed."

echo "Script completed."
