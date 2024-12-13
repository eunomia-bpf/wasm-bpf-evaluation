// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdbool.h>
#include "bootstrap.skel.h"
#include "bootstrap.wasm.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
// 环境变量结构体
static struct env {
    bool verbose;
    long min_duration_ms;
    uint64_t count;
    bool first_event;
    char first_ts[32];  // 确保这是一个字符数组
    char last_ts[32];   // 确保这是一个字符数组
    uint64_t last_report_count;
    time_t last_report_time;
} env = { .count = 0, .first_event = true, .last_report_count = 0 };

// 程序版本和文档
const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
    "BPF bootstrap demo application.\n"
    "\n"
    "It traces process start and exits and shows associated \n"
    "information (filename, process duration, PID and PPID, etc).\n"
    "\n"
    "USAGE: ./bootstrap [-d <min-duration-ms>] -v\n";

// 打印使用说明
static void print_usage(void) {
    printf("%s\n", argp_program_version);
    printf("%s\n", argp_program_doc);
}

// 事件处理函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;
    #define TARGET_PROCESS_NAME "cargo"
    if (strcmp(e->comm, TARGET_PROCESS_NAME) != 0&& strcmp(e->comm, "collect2") != 0 && strcmp(e->comm, "rustc") != 0 && strcmp(e->comm, "ld") != 0 && strcmp(e->comm, "cc1") != 0 && strcmp(e->comm, "cc") != 0 && strcmp(e->comm, "clang") != 0 && strcmp(e->comm, "sed") != 0 && strcmp(e->comm, "rm") != 0 && strcmp(e->comm, "llvm-config") !=0) {
        return 0; // 非目标进程，忽略
    }
    
    // 获取当前时间
    time(&t);
    tm = localtime(&t);
    if (tm == NULL) {
        fprintf(stderr, "localtime returned NULL\n");
        return 0;
    }

    if (strftime(ts, sizeof(ts), "%H:%M:%S", tm) == 0) {
        fprintf(stderr, "strftime failed\n");
        return 0;
    }

    // 调试输出：检查 ts 是否正确生成
    // printf("Debug: ts = %s\n", ts);

    // 处理计数
    env.count++;

    if (env.first_event) {
        // 记录并打印第一个时间戳
        snprintf(env.first_ts, sizeof(env.first_ts), "%s", ts);
        printf("First Timestamp: %s\n", env.first_ts);
        env.first_event = false;
    }

    if (env.count % 10000 == 0) {
        // 记录并打印每10000次事件的时间戳
        snprintf(env.last_ts, sizeof(env.last_ts), "%s", ts);
        printf("Debug: env.last_ts set to %s\n", env.last_ts); // 调试输出
        printf("Event Count: %lu, Timestamp: %s\n", env.count, env.last_ts);
    }

    return 0;
}

static bool exiting = false;

// 信号处理函数
static void sig_handler(int sig) {
    exiting = true;
}

// 报告线程函数（可选，用于更多统计信息）
void *report_thread(void *arg) {
    while (!exiting) {
        sleep(10); // 每10秒报告一次
        uint64_t current_count = env.count;
        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, env.last_report_time);
        if (elapsed > 0) {
            double rate = (current_count - env.last_report_count) / elapsed;
            printf("Total Events: %lu, Events in last %.0f seconds: %lu, Rate: %.2f events/sec\n",
                   current_count, elapsed, current_count - env.last_report_count, rate);
            env.last_report_count = current_count;
            env.last_report_time = current_time;
        }

        // 确保在打印 env.last_ts 之前，它已被设置
        if (env.count >= 10000 && env.count % 10000 == 0) {
            printf("Report Thread: Event Count: %lu, Timestamp: %s\n", env.count, env.last_ts);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
#ifdef NATIVE_LIBBPF
    struct ring_buffer *rb = NULL;
#else
    struct bpf_buffer *rb = NULL;
#endif

    struct bootstrap_bpf *skel;
    int err;

    // 解析参数
    if (argc > 3 || (argc == 2 && (strcmp(argv[1], "-h") == 0 ||
                                   strcmp(argv[1], "--help") == 0))) {
        print_usage();
        return 0;
    } else if (argc == 3 && (strcmp(argv[1], "-d") == 0 ||
                             strcmp(argv[1], "--duration") == 0)) {
        env.min_duration_ms = strtol(argv[2], NULL, 10);
    }


    // 初始化环境变量
    env.count = 0;
    env.first_event = true;
    env.last_report_count = 0;
    time(&env.last_report_time);

    /* 加载和验证 BPF 应用 */
    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* 使用最小持续时间参数对 BPF 代码进行参数化 */
    skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

    /* 加载和验证 BPF 程序 */
    err = bootstrap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* 附加跟踪点 */
    err = bootstrap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    puts("Attach ok!");
    fflush(stdout);

    /* 设置环形缓冲区轮询 */
#ifdef NATIVE_LIBBPF
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
#else
    rb = bpf_buffer__open(skel->maps.rb, handle_event, NULL);
#endif
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* 打印表头 */
    printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID",
           "PPID", "FILENAME/EXIT CODE");

    /* 处理事件 */
    while (!exiting) {
        // 轮询缓冲区
#ifndef NATIVE_LIBBPF
        err = bpf_buffer__poll(rb, 100 /* 超时, ms */);
#else
        err = ring_buffer__poll(rb, 100);
#endif
        /* Ctrl-C 将导致 -EINTR */
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
#ifdef NATIVE_LIBBPF
    ring_buffer__free(rb);
#else
    bpf_buffer__free(rb);
#endif
    bootstrap_bpf__destroy(skel);

    // 等待报告线程结束
    exiting = true;

    return err < 0 ? -err : 0;
}
