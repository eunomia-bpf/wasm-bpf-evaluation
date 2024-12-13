// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#ifndef NATIVE_LIBBPF
#include "libbpf-wasm.h"
#endif
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "trace_helpers.h"

#include <sys/types.h>

// typedef uint32_t __u32;
// typedef uint64_t __u64;

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES 64
#define PERF_BUFFER_TIME_MS 10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS 100

#define NSEC_PER_SEC 1000000000ULL

// static volatile sig_atomic_t exiting = 0;

static struct env {
  pid_t pid;
  pid_t tid;
  uid_t uid;
  int duration;
  bool verbose;
  bool timestamp;
  bool print_uid;
  bool extended;
  bool failed;
  char *name;
  
  // 新增字段：事件计数器和标志位
  uint64_t count;
  bool first_event;
} env = {.uid = INVALID_UID, .count = 0, .first_event = true, .name="a.out"};

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;
  char ts[32];
  time_t t;

  /* name filtering is currently done in user space */
  if (env.name && strstr(e->comm, env.name) == NULL)
    return 0;

  /* prepare fields */
  time(&t);
  struct tm *tm = localtime(&t);
  if (tm == NULL) {
    fprintf(stderr, "localtime returned NULL\n");
    return 0;
  }

  if (strftime(ts, sizeof(ts), "%H:%M:%S", tm) == 0) {
    fprintf(stderr, "strftime failed\n");
    return 0;
  }

  /* 增加事件计数 */
  env.count++;

  /* 如果是第一个事件，打印时间戳 */
  if (env.first_event) {
    printf("First Timestamp: %s\n", ts);
    env.first_event = false;
  }

  /* 每10000个事件打印一次时间戳 */
  if (env.count % 1000 == 0) {
    printf("Debug: env.last_ts set to %s\n", ts); // 调试输出
    printf("Event Count: %lu, Timestamp: %s\n", env.count, ts);
  }

  return 0;
}

static void handle_event_wrapper(void *ctx, int cpu, void *data,
                                 unsigned int data_sz) {
  handle_event(ctx, data, data_sz);
}

static void lost_event(void *a, int b, unsigned long long c) {}

int main(int argc, char **argv) {
  struct opensnoop_bpf *obj;
  unsigned long time_end = 0;
  int err;

  obj = opensnoop_bpf__open();
  if (!obj) {
    fprintf(stdout, "failed to open BPF object\n");
    return 1;
  }

  /* initialize global data (filtering options) */
  obj->rodata->targ_tgid = env.pid;
  obj->rodata->targ_pid = env.tid;
  obj->rodata->targ_uid = env.uid;
  obj->rodata->targ_failed = env.failed;

  /* aarch64 and riscv64 don't have open syscall */
  if (!tracepoint_exists("syscalls", "sys_enter_open")) {
    bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_enter_open, false);
    bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_exit_open, false);
  }

  err = opensnoop_bpf__load(obj);
  if (err) {
    fprintf(stdout, "failed to load BPF object: %d\n", err);
    goto cleanup;
  }

  err = opensnoop_bpf__attach(obj);
  if (err) {
    fprintf(stdout, "failed to attach BPF programs\n");
    goto cleanup;
  }
  printf("attach ok\n");

  /* print headers */
  // 由于我们只打印时间戳，调整表头
  if (env.timestamp) {
    printf("%-8s ", "TIME");
  }
  printf("%s\n", "EVENT");

  /* setup event callbacks */
#ifdef NATIVE_LIBBPF
  struct perf_buffer *buf = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                                            handle_event_wrapper, lost_event, NULL, NULL);
#else
  struct bpf_buffer *buf = bpf_buffer__open(obj->maps.events, handle_event, NULL);
#endif

  if (!buf) {
    err = -errno;
    fprintf(stdout, "failed to open perf buffer: %d\n", err);
    goto cleanup;
  }

  /* setup duration */
  if (env.duration)
    time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

  /* main: poll */
  while (true) {
#ifdef NATIVE_LIBBPF
    err = perf_buffer__poll(buf, PERF_BUFFER_TIME_MS);
#else
    err = bpf_buffer__poll(buf, PERF_BUFFER_TIME_MS);
#endif
    if (err < 0 && err != -EINTR) {
      fprintf(stdout, "error polling perf buffer: %s\n", strerror(-err));
      goto cleanup;
    }
    if (env.duration && get_ktime_ns() > time_end)
      goto cleanup;
    /* reset err to return 0 if exiting */
    err = 0;
  }

cleanup:
#ifdef NATIVE_LIBBPF
  perf_buffer__free(buf);
#else
  bpf_buffer__free(buf);
#endif
  opensnoop_bpf__destroy(obj);
  return err != 0;
}
