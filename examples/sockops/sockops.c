// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef NATIVE_LIBBPF
#include "libbpf-wasm.h"
#endif
// #include "sockops.h"
#include "sockops.skel.h"
#include "trace_helpers.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <time.h>

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t) - 1)
// typedef unsigned long long uint64_t;

struct args_t {
  const char *fname;
  int flags;
};

// 定义事件结构（根据 BPF 程序的实际事件结构进行定义）
struct event {
  pid_t pid;
  char comm[16];
  int fd;
  int err;
  char fname[256];
  // 根据需要添加其他字段
};

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES 64
#define PERF_BUFFER_TIME_MS 10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS 100

#define NSEC_PER_SEC 1000000000ULL

// 环境变量结构体
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
} env = {.uid = INVALID_UID, .count = 0, .first_event = true};

// 事件处理函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;
  char ts[32];
  time_t t;
  struct tm *tm_info;

  // 过滤特定进程名（如果设置了）
  if (env.name && strstr(e->comm, env.name) == NULL)
    return 0;

  // 获取当前时间
  time(&t);
  tm_info = localtime(&t);
  if (tm_info == NULL) {
    fprintf(stderr, "localtime returned NULL\n");
    return 0;
  }

  if (strftime(ts, sizeof(ts), "%H:%M:%S", tm_info) == 0) {
    fprintf(stderr, "strftime failed\n");
    return 0;
  }

  // 增加事件计数
  env.count++;

  // 如果是第一个事件，打印时间戳
  if (env.first_event) {
    printf("First Timestamp: %s\n", ts);
    env.first_event = false;
  }

  // 每10000个事件打印一次时间戳
  if (env.count % 10000 == 0) {
    printf("Event Count: %lu, Timestamp: %s\n", env.count, ts);
  }

  return 0;
}

// 事件处理函数的包装器
static void handle_event_wrapper(void *ctx, int cpu, void *data,
                                 unsigned int data_sz) {
  handle_event(ctx, data, data_sz);
}

// 丢失事件的处理函数（可以根据需要实现）
static void lost_event(void *a, int b, unsigned long long c) {}

// 主函数
int main(int argc, char **argv) {
  struct sockops_bpf *skel = NULL;
  uint64_t time_end = 0;
  int err;

  // 打开 BPF 对象
  skel = sockops_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
    return 1;
  }
  printf("Successfully opened BPF object\n");
  if (env.timestamp) {
    printf("%-8s ", "TIME");
  }
  if (env.print_uid) {
    printf("%-7s ", "UID");
  }
  printf("%-6s %-16s %3s %3s ", "PID", "COMM", "FD", "ERR");
  if (env.extended) {
    printf("%-8s ", "FLAGS");
  }
  printf("%s\n", "PATH");

  /* setup event callbacks */
#ifdef NATIVE_LIBBPF
  struct perf_buffer *buf =
      perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
                       handle_event_wrapper, lost_event, NULL, NULL);
#else
  struct bpf_buffer *buf =
      bpf_buffer__open(skel->maps.rodata, handle_event, NULL);
#endif

  if (!buf) {
    err = -errno;
    printf("Failed to open perf buffer: %d\n", err);
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
      printf("Error polling perf buffer: %s\n", strerror(-err));
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
  sockops_bpf__destroy(skel);
  return err != 0;
}
