#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, long);
  __type(value, long);
} test_map SEC(".maps");
SEC("tp/syscalls/sys_enter_execve")
int sys_enter_execve(void *ctx) {
    return 0;
}
