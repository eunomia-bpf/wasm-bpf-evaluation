// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdbool.h>
#include "bootstrap.skel.h"
#include "bootstrap.wasm.h"

#include <stdio.h>
#include <time.h>

static struct env {
  bool verbose;
  long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
    "BPF bootstrap demo application.\n"
    "\n"
    "It traces process start and exits and shows associated \n"
    "information (filename, process duration, PID and PPID, etc).\n"
    "\n"
    "USAGE: ./bootstrap [-d <min-duration-ms>] -v\n";

static void print_usage(void) {
  printf("%s\n", argp_program_version);
  printf("%s\n", argp_program_doc);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (e->exit_event) {
    printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid,
           e->ppid, e->exit_code);
    if (e->duration_ns)
      printf(" (%llums)", e->duration_ns / 1000000);
    printf("\n");
  } else {
    printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid,
           e->ppid, e->filename);
  }

  return 0;
}

static bool exiting = false;

int main(int argc, char **argv) {
#ifndef NATIVE_LIBBPF
  struct bpf_buffer *rb = NULL;
#else
  struct ring_buffer *rb = NULL;
#endif

  struct bootstrap_bpf *skel;
  int err;

  // parse the args manually for demo purpose
  if (argc > 3 || (argc == 2 && (strcmp(argv[1], "-h") == 0 ||
                                 strcmp(argv[1], "--help") == 0))) {
    print_usage();
    return 0;
  } else if (argc == 3 && (strcmp(argv[1], "-d") == 0 ||
                           strcmp(argv[1], "--duration") == 0)) {
    env.min_duration_ms = strtol(argv[2], NULL, 10);
  }

  /* Load and verify BPF application */
  skel = bootstrap_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Parameterize BPF code with minimum duration parameter */
  skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

  /* Load & verify BPF programs */
  err = bootstrap_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = bootstrap_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

/* Set up ring buffer polling */
#ifndef NATIVE_LIBBPF
  rb = bpf_buffer__open(skel->maps.rb, handle_event, NULL);
#else
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
#endif
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  /* Process events */
  printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID",
         "PPID", "FILENAME/EXIT CODE");
  while (!exiting) {
// poll buffer
#ifndef NATIVE_LIBBPF
    err = bpf_buffer__poll(rb, 100 /* timeout, ms */);
#else
    err = ring_buffer__poll(rb, 100);
#endif
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
#ifdef WASM_BPF
  bpf_buffer__free(rb);
#else
  ring_buffer__free(rb);
#endif
  bootstrap_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}
