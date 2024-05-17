#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "uprobe.h"
char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/./target:uprobe_add")
int BPF_KPROBE(uprobe_add, int a, int b) {
  struct uprobe_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct uprobe_event), 0);
  if (!e)
    return 0;
  e->a = a;
  e->b = b;
  bpf_ringbuf_submit(e, 0);
  return 0;
}
