#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define u32 __u32
#define u64 __u64
#define size_t __u64
#define ssize_t __s64

// Define a map to store timestamps for latency calculation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u64);
} start_time SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

// Entry probe for send()
SEC("uprobe/libc.so:send")
int BPF_KPROBE(send_entry, int fd, const void *buf, size_t len, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    if (pid == 1) {
        bpf_printk("send entry: pid = %d, fd = %d, len = %lu", pid, fd, len);
    }
    bpf_map_update_elem(&start_time, &pid, &ts, BPF_ANY);
    return 0;
}

// Return probe for send()
SEC("uretprobe/libc.so:send")
int BPF_KRETPROBE(send_exit, ssize_t ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp, delta;
    
    tsp = bpf_map_lookup_elem(&start_time, &pid);
    if (!tsp)
        return 0;
        
    delta = bpf_ktime_get_ns() - *tsp;
    bpf_printk("send exit: pid = %d, ret = %ld, latency = %lu ns", 
               pid, ret, delta);
               
    bpf_map_delete_elem(&start_time, &pid);
    return 0;
}

// Entry probe for recv()
SEC("uprobe/libc.so:recv") 
int BPF_KPROBE(recv_entry, int fd, void *buf, size_t len, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&start_time, &pid, &ts, BPF_ANY);
    bpf_printk("recv entry: pid = %d, fd = %d, len = %lu", pid, fd, len);
    return 0;
}

// Return probe for recv()
SEC("uretprobe/libc.so:recv")
int BPF_KRETPROBE(recv_exit, ssize_t ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp, delta;
    
    tsp = bpf_map_lookup_elem(&start_time, &pid);
    if (!tsp)
        return 0;
        
    delta = bpf_ktime_get_ns() - *tsp;
    bpf_printk("recv exit: pid = %d, ret = %ld, latency = %lu ns",
               pid, ret, delta);
               
    bpf_map_delete_elem(&start_time, &pid);
    return 0;
}