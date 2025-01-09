#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef NATIVE_LIBBPF
#include "libbpf-wasm.h"
#endif
#include "uprobe.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

// 通过进程名查找PID
static int find_pid_by_name(const char *process_name) {
  DIR *dir;
  struct dirent *ent;
  char path[512];
  char cmdline[512];
  FILE *fp;

  dir = opendir("/proc");
  if (!dir) {
    perror("Failed to open /proc");
    return -1;
  }

  while ((ent = readdir(dir)) != NULL) {
    // 检查是否为数字（PID）
    if (!isdigit(*ent->d_name))
      continue;

    snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
    fp = fopen(path, "r");
    if (!fp)
      continue;

    if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
      // 移除命令行参数，只比较程序名
      char *first_space = strchr(cmdline, ' ');
      if (first_space)
        *first_space = '\0';

      // 获取基本名称
      char *base_name = strrchr(cmdline, '/');
      base_name = base_name ? base_name + 1 : cmdline;

      if (strcmp(base_name, process_name) == 0) {
        int pid = atoi(ent->d_name);
        fclose(fp);
        closedir(dir);
        return pid;
      }
    }
    fclose(fp);
  }
  closedir(dir);
  return -1;
}

int main(int argc, char *argv[]) {
  struct uprobe_bpf *skel = NULL;
  int err;

  // 检查命令行参数
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <process_name>\n", argv[0]);
    return 1;
  }

  // 设置信号处理
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // 查找目标进程
  int target_pid = find_pid_by_name(argv[1]);
  if (target_pid < 0) {
    fprintf(stderr, "Failed to find process: %s\n", argv[1]);
    return 1;
  }
  printf("Found target process %s with PID: %d\n", argv[1], target_pid);

  skel = uprobe_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = uprobe_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    uprobe_bpf__destroy(skel);
    return 1;
  }

  printf("Successfully loaded and attached BPF uprobe\n");
  printf("Tracing... Hit Ctrl-C to end.\n");

  // 主循环：监控直到收到信号
  while (!exiting) {
    // 这里可以添加从 BPF map 读取数据的逻辑
    sleep(1);
  }

  printf("\nCleaning up...\n");
  uprobe_bpf__destroy(skel);
  return 0;
}
