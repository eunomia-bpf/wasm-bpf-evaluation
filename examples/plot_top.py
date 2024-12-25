import matplotlib.pyplot as plt

def parse_top_log(file_path):
    cpu_values = []
    mem_values = []

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # 跳过表头行
            if line.startswith('%CPU %MEM CMD'):
                continue
            # 尝试解析CPU和MEM值
            parts = line.split()
            if len(parts) >= 2:
                try:
                    cpu = float(parts[0])
                    mem = float(parts[1])
                    cpu_values.append(cpu)
                    mem_values.append(mem)
                except ValueError:
                    # 如果转换失败，可能是空行或非数据行
                    pass

    return cpu_values, mem_values

def plot_cpu_mem(cpu_values, mem_values, interval=0.1):
    # 根据数据点数量生成时间序列
    times = [i*interval for i in range(len(cpu_values))]

    plt.figure(figsize=(10,5))
    plt.plot(times, cpu_values, label='CPU (%)', marker='o')
    plt.plot(times, mem_values, label='Memory (%)', marker='s')

    plt.xlabel('Time (s)')
    plt.ylabel('Usage (%)')
    plt.title('CPU and Memory Usage Over Time')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("opensnoop_top.pdf")

if __name__ == "__main__":
    log_file = './opensnoop/top.txt'  # 修改为您的日志文件路径
    cpu_values, mem_values = parse_top_log(log_file)
    plot_cpu_mem(cpu_values, mem_values, interval=0.1)
