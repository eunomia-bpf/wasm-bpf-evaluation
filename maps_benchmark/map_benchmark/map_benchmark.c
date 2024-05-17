#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#ifdef NATIVE_LIBBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#else
#include "libbpf-wasm.h"
#endif
#include "map_benchmark.skel.h"

#define NANO_SECOND_TO_TEST ((uint64_t)1000 * 1000 * 1000 * 3)

#define TEST_COUNT 1000000

static uint64_t get_timestamp() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec * (uint64_t)1000000000 + ts.tv_nsec;
}

int main(int argc, char *argv[]) {
  int err;

  struct map_benchmark_bpf *skel = map_benchmark_bpf__open();
  if (!skel) {
    fprintf(stderr, "Unable to open skeleton\n");
    return 1;
  }
  err = map_benchmark_bpf__load(skel);
  if (err < 0) {
    fprintf(stderr, "Unable to load\n");
    goto cleanup;
  }
  int mapfd = bpf_map__fd(skel->maps.test_map);
  for (int64_t i = 1; i <= 100; i++) {
    int64_t value = (i << 32) | i;
    bpf_map_update_elem(mapfd, &i, &value, 0);
  }
  // uint64_t count = 0;
  uint64_t start = get_timestamp();
  for (int i = 1; i <= 1000000; i++) {
    int64_t key = 10;
    int64_t value_out;
    bpf_map_lookup_elem(mapfd, &key, &value_out);
    // count++;
  }
  uint64_t time_elapsed = get_timestamp() - start;
  printf("%" PRIu64 " %" PRIu64 "\n", time_elapsed, (uint64_t)TEST_COUNT);
cleanup:
  map_benchmark_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}
