#include <stddef.h>
#define _GNU_SOURCE
#include "libbpf-wasm.h"
#include "uprobe.skel.h"
#include "wbpf.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

struct latency_key {
  uint32_t pid;
  uint64_t timestamp;
};

struct latency_value {
  uint64_t duration;
  char comm[16];
};

#define MAX_ENTRIES 1000
#define P99_THRESHOLD 100000000 // 100ms in nanoseconds
#define HOOKER_PORT 8888
#define LATENCY_THRESHOLD_MS 100 // 100ms threshold for tail latency

static volatile int should_exit = 0;
static struct uprobe_bpf *skel = NULL;
static int hooker_sock = -1;
void sig_handler(int sig) { should_exit = 1; }

static int setup_hooker_server() {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(HOOKER_PORT);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    fprintf(stderr, "Failed to bind socket\n");
    close(sock);
    return -1;
  }

  return sock;
}
// Function to set up connection with hooker process
static int setup_hooker_socket(char *hooker_ip) {
  hooker_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (hooker_sock < 0) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(HOOKER_PORT);
  inet_pton(AF_INET, hooker_ip, &server_addr.sin_addr);

  if (connect(hooker_sock, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0) {
    fprintf(stderr, "Failed to connect to hooker process\n");
    close(hooker_sock);
    return -1;
  }

  return hooker_sock;
}
static char **get_hooker_ip(int sock) {
  static char ips[10][16]; // Static array to store IPs
  memset(ips, 0, sizeof(ips));

  char *buffer = (char *)malloc(200);
  if (!buffer) {
    fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }

  if (recv(sock, buffer, sizeof(buffer), 0) < 0) {
    fprintf(stderr, "Failed to receive hooker IP\n");
    free(buffer);
    return NULL;
  }

  buffer[strcspn(buffer, "\n")] = '\0';
  struct wbpf_sync_info *sync_info = (struct wbpf_sync_info *)buffer;

  if (sync_info->sync_mode == WBPF_SYNC_NOTIFY ||
      sync_info->sync_mode == WBPF_SYNC_FLUSH) {
    // Copy IPs to static array
    for (int i = 0; i < 10 && sync_info->sync_ip[i][0] != '\0'; i++) {
      strncpy(ips[i], sync_info->sync_ip[i], 15);
      ips[i][15] = '\0'; // Ensure null termination
    }
    free(buffer);
    return (char **)ips;
  }

  if (sync_info->sync_mode == WBPF_SYNC_COLLECT) {
    // Collect all latency data for the trace ID
    char response[4096] = {0}; // Buffer for response
    int offset = 0;

    // Add trace ID to response
    offset += snprintf(response + offset, sizeof(response) - offset,
                       "TRACE_ID:%lu\n", sync_info->trace_id);

    // Collect latency data from BPF map
    bpf_object_skel obj = (bpf_object_skel)(uintptr_t)skel->obj;
    int map_fd = wasm_bpf_map_fd_by_name(obj, "latency_map");
    if (map_fd >= 0) {
      struct latency_key key = {}, next_key = {};
      struct latency_value value;

      // Iterate through all entries
      while (wasm_bpf_map_operate(map_fd, BPF_MAP_GET_NEXT_KEY, &key, NULL,
                                  &next_key, 0) == 0) {
        if (wasm_bpf_map_operate(map_fd, BPF_MAP_LOOKUP_ELEM, &next_key, &value,
                                 NULL, 0) == 0) {
          // Add latency data to response
          offset += snprintf(response + offset, sizeof(response) - offset,
                             "PID:%u,COMM:%s,LATENCY:%lu\n", next_key.pid,
                             value.comm, value.duration);

          // Delete processed entry
          wasm_bpf_map_operate(map_fd, BPF_MAP_DELETE_ELEM, &next_key, NULL,
                               NULL, 0);
        }
        key = next_key;
      }
    }

    // Send collected data back to initiator
    if (send(sock, response, strlen(response), 0) < 0) {
      fprintf(stderr, "Failed to send latency data back to initiator\n");
    }

    free(buffer);
    return NULL;
  }

  free(buffer);
  return NULL;
}

static void *hooker_thread_func(void *arg) {
  int server_sock = setup_hooker_server();
  if (server_sock < 0) {
    fprintf(stderr, "Failed to setup hooker server\n");
    return NULL;
  }

  if (listen(server_sock, 5) < 0) {
    fprintf(stderr, "Failed to listen\n");
    close(server_sock);
    return NULL;
  }

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);

  while (!should_exit) {
    hooker_sock =
        accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
    if (hooker_sock < 0) {
      fprintf(stderr, "Failed to accept connection\n");
      continue;
    }

    char **hooker_ips = get_hooker_ip(hooker_sock);
    if (hooker_ips && hooker_ips[0]) {
      // Try to connect to the first IP
      if (setup_hooker_socket(hooker_ips[0]) < 0) {
        fprintf(stderr, "Warning: Could not connect to hooker process\n");
      }
    }

    close(hooker_sock);
  }

  close(server_sock);
  return NULL;
}

static void send_alert_to_hooker(int sock, struct latency_key *key,
                                 struct latency_value *value) {
  if (sock < 0)
    return;

  char buffer[256];
  snprintf(buffer, sizeof(buffer),
           "TAIL_LATENCY_ALERT: PID=%u COMM=%s DURATION=%lu ms\n", key->pid,
           value->comm, value->duration / 1000000);

  if (send(sock, buffer, strlen(buffer), 0) < 0) {
    fprintf(stderr, "Failed to send alert to hooker\n");
  }
}

static uint64_t calculate_p99(struct latency_value *latencies, int count) {
  // Strict bounds checking
  if (count <= 0 || latencies == NULL) {
    return 0;
  }

  // For small sample sizes, just return the maximum
  uint64_t max_duration = latencies[0].duration;

  // If only one sample, return it
  if (count == 1) {
    return max_duration;
  }

  // For multiple samples, find the maximum
  for (int i = 1; i < count && i < MAX_ENTRIES; i++) {
    if (latencies[i].duration > max_duration) {
      max_duration = latencies[i].duration;
    }
  }

  // If less than 100 samples, return the maximum
  if (count < 100) {
    return max_duration;
  }

  // For larger sample sizes, do proper P99 calculation
  // Simple bubble sort for demonstration
  int sort_count = count < MAX_ENTRIES ? count : MAX_ENTRIES;
  for (int i = 0; i < sort_count - 1; i++) {
    for (int j = 0; j < sort_count - i - 1; j++) {
      if (latencies[j].duration > latencies[j + 1].duration) {
        struct latency_value temp = latencies[j];
        latencies[j] = latencies[j + 1];
        latencies[j + 1] = temp;
      }
    }
  }

  // Calculate P99 index safely
  sort_count = count < MAX_ENTRIES ? count : MAX_ENTRIES;
  int p99_index = (sort_count * 99) / 100; // More precise P99 calculation
  if (p99_index < 0) {
    p99_index = 0;
  }
  if (p99_index >= sort_count) {
    p99_index = sort_count - 1;
  }

  return latencies[p99_index].duration;
}

int main(int argc, char **argv) {
  // Set up signal handler
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  pthread_t hooker_thread;
  pthread_create(&hooker_thread, NULL, hooker_thread_func, NULL);

  // Open and load BPF program
  skel = uprobe_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF program\n");
    return 1;
  }

  // Get map file descriptor
  bpf_object_skel obj = (bpf_object_skel)(uintptr_t)skel->obj;
  int map_fd = wasm_bpf_map_fd_by_name(obj, "latency_map");
  if (map_fd < 0) {
    fprintf(stderr, "Failed to get map fd\n");
    goto cleanup;
  }

  struct latency_value latencies[MAX_ENTRIES];
  int latency_count = 0;

  while (!should_exit) {
    struct latency_key key = {}, next_key = {};
    struct latency_value value;

    // Reset latency count for this iteration
    latency_count = 0;

    // Get all entries from the map
    while (wasm_bpf_map_operate(map_fd, BPF_MAP_GET_NEXT_KEY, &key, NULL,
                                &next_key, 0) == 0) {
      if (wasm_bpf_map_operate(map_fd, BPF_MAP_LOOKUP_ELEM, &next_key, &value,
                               NULL, 0) == 0) {
        // Store for P99 calculation
        if (latency_count < MAX_ENTRIES) {
          latencies[latency_count++] = value;
        }

        // Check for immediate tail latency
        if (value.duration > LATENCY_THRESHOLD_MS * 1000000) {
          printf("Tail latency detected in %s (PID: %u) - Duration: %lu ms\n",
                 value.comm, next_key.pid, value.duration / 1000000);

          send_alert_to_hooker(hooker_sock, &next_key, &value);
        }

        // Delete the processed entry
        wasm_bpf_map_operate(map_fd, BPF_MAP_DELETE_ELEM, &next_key, NULL, NULL,
                             0);
      }
      key = next_key;
    }

    // Calculate and report P99 latency
    if (latency_count > 0) {
      uint64_t p99 = calculate_p99(latencies, latency_count);
      printf("P99 latency: %llu ms (from %d samples)\n", p99 / 1000000,
             latency_count);

      if (p99 > P99_THRESHOLD) {
        printf("Warning: P99 latency exceeds threshold!\n");
      }
    }

    sleep(1);
  }

cleanup:
  printf("\nCleaning up...\n");
  if (skel) {
    uprobe_bpf__destroy(skel);
  }

  return 0;
}