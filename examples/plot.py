import re
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

def parse_log(file_path):
    """
    解析日志文件，提取事件计数和对应的时间戳。
    返回基准时间 t0、事件计数列表和相应的相对时间列表。
    """
    event_counts = []
    event_times = []
    t0 = None
    current_debug_ts = None

    # 定义正则表达式模式
    first_ts_pattern = re.compile(r'First Timestamp: (\d{2}:\d{2}:\d{2})')
    debug_ts_pattern = re.compile(r'Debug: env\.last_ts set to (\d{2}:\d{2}:\d{2})')
    event_count_pattern = re.compile(r'Event Count: (\d+), Timestamp: \((null|)\)')

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # 匹配第一个时间戳
            m = first_ts_pattern.match(line)
            if m:
                t0_str = m.group(1)
                t0 = datetime.strptime(t0_str, "%H:%M:%S")
                continue

            # 匹配 Debug 更新的时间戳
            m = debug_ts_pattern.match(line)
            if m:
                current_debug_ts_str = m.group(1)
                current_debug_ts = datetime.strptime(current_debug_ts_str, "%H:%M:%S")
                continue

            # 匹配事件计数
            m = event_count_pattern.match(line)
            if m:
                count = int(m.group(1))
                ts_str = m.group(2)
                if current_debug_ts:
                    # 假设所有事件在同一天内
                    # 如果当前调试时间早于 t0，假设跨日
                    if current_debug_ts < t0:
                        current_debug_ts += timedelta(days=1)
                    # 计算相对时间（秒）
                    elapsed = (current_debug_ts - t0).total_seconds()
                    event_counts.append(count)
                    event_times.append(elapsed)
                    # 重置当前调试时间
                    current_debug_ts = None
                continue

    return t0, event_counts, event_times

def plot_events(event_counts, event_times, event_counts1, event_times1):
    """
    绘制事件计数与时间的关系图。
    """
    plt.figure(figsize=(12, 6))
    plt.plot(event_times, event_counts, marker='o', linestyle='-')
    plt.plot(event_times1, event_counts1, marker='o', linestyle='-')
    plt.xlabel('Elapsed Time (seconds)')
    plt.ylabel('Event Count')
    plt.title('Event Count Over Time')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('sockops.pdf')

if __name__ == "__main__":
    log_file = './sockops/sockops.txt'  # 替换为您的日志文件路径
    log_file1 = './sockops/sockops1.txt'  # 替换为您的日志文件路径
    t0, counts, times = parse_log(log_file)
    t1, counts1, times1 = parse_log(log_file1)
    if t0:
        print(f"First Timestamp: {t0.strftime('%H:%M:%S')}")
    else:
        print("First Timestamp not found.")
    print("Event Counts:", counts)
    print("Event Times (s):", times)
    plot_events(counts, times, counts1, times1)
