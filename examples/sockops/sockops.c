#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef NATIVE_LIBBPF
#include "libbpf-wasm.h"
#endif
#include "sockops.skel.h"

int main(void) {
  struct sockops_bpf *skel = NULL;
  int err;

  skel = sockops_bpf__open_and_load();
  if (!skel) {
    printf("Failed to open and load BPF skeleton\n");
    return -1;
  }
#ifdef NATIVE_LIBBPF
  bpf_program__set_attach_target(
      skel->progs.pid_tcp_opt_inject,
      bpf_program__fd(skel->progs.pid_tcp_opt_inject), "/sys/fs/cgroup");
#else

  bpf_set_prog_attach_target(skel->progs.pid_tcp_opt_inject, "/sys/fs/cgroup/");
#endif

  err = sockops_bpf__attach(skel);
  if (err) {
    printf("Failed to attach BPF skeleton\n");
    return -1;
  }
  printf("Load and attach BPF sockops successfully\n");
  while (1) {
    sleep(10);
  }
}
