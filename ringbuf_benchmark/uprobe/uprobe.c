#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#ifndef NATIVE_LIBBPF
#include "libbpf-wasm.h"
#else
#include <signal.h>
#endif
#include "uprobe.skel.h"

#define NANO_SECOND_TO_RUN ((uint64_t)1000 * 1000 * 1000 * 3)

static uint64_t count = 0;

static int handle_event(void *ctx, void *data, size_t data_sz) {
  count++;
  return 0;
}

static uint64_t get_timestamp() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char *argv[]) {
  struct uprobe_bpf *skel = NULL;
  int err;

#ifdef NATIVE_LIBBPF
  int child_pid = fork();
  if (child_pid < 0) {
    err = child_pid;
    printf("Unable to fork");
    goto cleanup;
  }

  if (child_pid == 0) {
    execl("./target", "./target", NULL);
  }
#endif

  skel = uprobe_bpf__open_and_load();
  if (!skel) {
    printf("Failed to open and load BPF skeleton\n");
    err = -1;
    goto cleanup;
  }
  puts("Before attach");
  err = uprobe_bpf__attach(skel);
  if (err) {
    printf("Failed to attach BPF skeleton\n");
    err = -1;
    goto cleanup;
  }

  printf("Load and attach BPF uprobe successfully\n");

#ifdef NATIVE_LIBBPF
  struct ring_buffer *rb =
      ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
#else
  struct bpf_buffer *rb = bpf_buffer__open(skel->maps.rb, handle_event, NULL);
#endif
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  uint64_t start_time = get_timestamp();
  //   printf("%lu, %lu\n",start_time,get_timestamp_quick());
  // while (get_timestamp() - start_time < NANO_SECOND_TO_RUN)
  for (int i = 1; i <= 1000000; i++) {
#ifdef NATIVE_LIBBPF
    err = ring_buffer__poll(rb, 1);
#else
    err = bpf_buffer__poll(rb, 1 /* timeout, ms */);
#endif
  }
  uint64_t total_time = get_timestamp() - start_time;
  printf("Total nanoseconds: %" PRIu64 ", total polled events: %" PRIu64
         ", events per millisecond: %f\n",
         total_time, count, (double)count / (((double)total_time) / 1000000));
  printf("%" PRIu64 " %" PRIu64, total_time, count);

cleanup:

#ifdef NATIVE_LIBBPF
  if (child_pid > 0)
    kill(child_pid, SIGTERM);
  ring_buffer__free(rb);
#else
  bpf_buffer__free(rb);
#endif
  uprobe_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}
