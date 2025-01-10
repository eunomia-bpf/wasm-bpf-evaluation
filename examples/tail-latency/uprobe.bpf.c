#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <stddef.h>

#define MAX_ENTRIES 10000
#define LATENCY_THRESHOLD 100000000 // 100ms in nanoseconds

struct latency_key {
  __u32 pid;
  __u64 timestamp;
};

struct latency_value {
  __u64 duration;
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct latency_key);
  __type(value, struct latency_value);
} latency_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/libc.so:send")
int send_entry(struct pt_regs *ctx) {
  struct latency_key key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  key.timestamp = bpf_ktime_get_ns();

  struct latency_value value = {};
  value.duration = 0;
  bpf_get_current_comm(&value.comm, sizeof(value.comm));

  bpf_map_update_elem(&latency_map, &key, &value, BPF_ANY);
  return 0;
}

SEC("uretprobe/libc.so:send")
int send_exit(struct pt_regs *ctx) {
  struct latency_key key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  __u64 current_time = bpf_ktime_get_ns();

  struct latency_value *valuep;
  valuep = bpf_map_lookup_elem(&latency_map, &key);
  if (valuep) {
    valuep->duration = current_time - key.timestamp;
    if (valuep->duration > LATENCY_THRESHOLD) {
      bpf_printk("High latency detected in %s: %llu ns", valuep->comm,
                 valuep->duration);
    }
    bpf_map_delete_elem(&latency_map, &key);
  }
  return 0;
}

SEC("uprobe/libc.so:recv")
int recv_entry(struct pt_regs *ctx) {
  struct latency_key key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  key.timestamp = bpf_ktime_get_ns();

  struct latency_value value = {};
  value.duration = 0;
  bpf_get_current_comm(&value.comm, sizeof(value.comm));

  bpf_map_update_elem(&latency_map, &key, &value, BPF_ANY);
  return 0;
}

SEC("uretprobe/libc.so:recv")
int recv_exit(struct pt_regs *ctx) {
  struct latency_key key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  __u64 current_time = bpf_ktime_get_ns();

  struct latency_value *valuep;
  valuep = bpf_map_lookup_elem(&latency_map, &key);
  if (valuep) {
    valuep->duration = current_time - key.timestamp;
    if (valuep->duration > LATENCY_THRESHOLD) {
      bpf_printk("High latency detected in %s: %llu ns", valuep->comm,
                 valuep->duration);
    }
    bpf_map_delete_elem(&latency_map, &key);
  }
  return 0;
}