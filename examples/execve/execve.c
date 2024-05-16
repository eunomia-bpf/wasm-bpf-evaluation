#include <stdbool.h>
#include "execve.h"
#include "execve.skel.h"

#ifndef NATIVE_LIBBPF
#include "libbpf-wasm.h"
#endif
#include <stdio.h>
static int handle_event(void *ctx, void *data, size_t data_sz) {
  struct comm_event *st = (struct comm_event *)data;
  printf("[%d] %s -> %s\n", st->pid, st->parent_proc, st->command);
  return 0;
}

int main() {
  struct execve_bpf *skel = execve_bpf__open_and_load();
  execve_bpf__attach(skel);
#ifdef NATIVE_LIBBPF
  struct ring_buffer *buf = ring_buffer__new(
      bpf_map__fd(skel->maps.comm_event), handle_event, NULL, NULL);

#else
  struct bpf_buffer *buf =
      bpf_buffer__open(skel->maps.comm_event, handle_event, NULL);

#endif
  while (1) {
    if (
#ifdef NATIVE_LIBBPF
        ring_buffer__poll(buf, 0)
#else
        bpf_buffer__poll(buf, 0)
#endif
        < 0)
      break;
  }
  return 0;
}
