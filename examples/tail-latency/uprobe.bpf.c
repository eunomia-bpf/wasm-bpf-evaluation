#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <linux/types.h>

#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

char LICENSE[] SEC("license") = "GPL";

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
  __uint(max_entries, 1000);
  __type(key, struct latency_key);
  __type(value, struct latency_value);
} latency_map SEC(".maps");

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
    bpf_map_delete_elem(&latency_map, &key);
  }
  return 0;
}