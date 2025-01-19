#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#define _GNU_SOURCE
#include "libbpf-wasm.h"
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

// Include BPF skeleton after all standard headers
#include "uprobe.skel.h"

// Function declarations
int wasm_bpf_prog_attach(bpf_object_skel obj, const char *name,
                         const char *path, const char *fn, bool is_return);

struct latency_key
{
  uint32_t pid;
  uint64_t timestamp;
};

struct latency_value
{
  uint64_t duration;
  char comm[16];
};

#define MAX_ENTRIES 1000
#define P99_THRESHOLD 1000000 // 100ms in nanoseconds
#define HOOKER_PORT 8888
#define LATENCY_THRESHOLD_MS 100 // 100ms threshold for tail latency
#define MAX_CLIENTS 100

static volatile int should_exit = 0;
static struct uprobe_bpf *skel = NULL;
static int hooker_sock = -1;
static int server_sock = -1;
static int client_sockets[MAX_CLIENTS];
static int client_count = 0;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void sig_handler(int sig) { should_exit = 1; }
static int add_client(int sock);
static void remove_client(int index);
static int setup_hooker_server()
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
  {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(HOOKER_PORT);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    fprintf(stderr, "Failed to bind socket\n");
    close(sock);
    return -1;
  }

  if (listen(sock, 5) < 0)
  {
    fprintf(stderr, "Failed to listen\n");
    close(sock);
    return -1;
  }

  return sock; // Just return the listening socket here
}

static int setup_hooker_socket(char *hooker_ip)
{
  hooker_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (hooker_sock < 0)
  {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(HOOKER_PORT);
  inet_pton(AF_INET, hooker_ip, &server_addr.sin_addr);

  if (connect(hooker_sock, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0)
  {
    fprintf(stderr, "Failed to connect to hooker process\n");
    close(hooker_sock);
    return -1;
  }

  return hooker_sock;
}

static char **get_hooker_ip(int sock)
{
  static char ips[10][16]; // Static array to store IPs
  memset(ips, 0, sizeof(ips));

  char *buffer = (char *)malloc(200);
  if (!buffer)
  {
    fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }

  if (recv(sock, buffer, sizeof(buffer), 0) < 0)
  {
    fprintf(stderr, "Failed to receive hooker IP\n");
    free(buffer);
    return NULL;
  }

  buffer[strcspn(buffer, "\n")] = '\0';
  struct wbpf_sync_info *sync_info = (struct wbpf_sync_info *)buffer;

  if (sync_info->sync_mode == WBPF_SYNC_NOTIFY ||
      sync_info->sync_mode == WBPF_SYNC_FLUSH)
  {
    // Copy IPs to static array
    for (int i = 0; i < 10 && sync_info->sync_ip[i][0] != '\0'; i++)
    {
      strncpy(ips[i], sync_info->sync_ip[i], 15);
      ips[i][15] = '\0'; // Ensure null termination
    }
    free(buffer);
    return (char **)ips;
  }

  if (sync_info->sync_mode == WBPF_SYNC_COLLECT)
  {
    // Collect all latency data for the trace ID
    char response[4096] = {0}; // Buffer for response
    int offset = 0;

    // Add trace ID to response
    offset += snprintf(response + offset, sizeof(response) - offset,
                       "TRACE_ID:%u\n", sync_info->trace_id);

    // Collect latency data from BPF map
    bpf_object_skel obj = (bpf_object_skel)(uintptr_t)skel->obj;
    int map_fd = wasm_bpf_map_fd_by_name(obj, "latency_map");
    if (map_fd >= 0)
    {
      struct latency_key key = {}, next_key = {};
      struct latency_value value;

      // Iterate through all entries
      while (wasm_bpf_map_operate(map_fd, BPF_MAP_GET_NEXT_KEY, &key, NULL,
                                  &next_key, 0) == 0)
      {
        if (wasm_bpf_map_operate(map_fd, BPF_MAP_LOOKUP_ELEM, &next_key, &value,
                                 NULL, 0) == 0)
        {
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
    if (send(sock, response, strlen(response), 0) < 0)
    {
      fprintf(stderr, "Failed to send latency data back to initiator\n");
    }

    free(buffer);
    return NULL;
  }

  free(buffer);
  return NULL;
}
static void *hooker_thread_func(void *arg) {
    int srv_sock = *(int *)arg;   // receive the listening socket
    printf("Server socket created and listening on port %d\n", HOOKER_PORT);

    // This is the infinite accept loop
    while (!should_exit) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(srv_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            sleep(1);
            continue;
        }

        int client_index = add_client(client_sock);
        if (client_index < 0) {
            fprintf(stderr, "Too many clients\n");
            close(client_sock);
            continue;
        }
        printf("New client connected, total clients: %d\n", client_count);
    }

    close(srv_sock);
    return NULL;
}

static void send_alert_to_hooker(int sock, struct latency_key *key,
                                 struct latency_value *value)
{
  if (sock < 0)
    return;

  char buffer[256];
  snprintf(buffer, sizeof(buffer),
           "TAIL_LATENCY_ALERT: PID=%u COMM=%s DURATION=%lu ms\n", key->pid,
           value->comm, value->duration / 1000000);

  if (send(sock, buffer, strlen(buffer), 0) < 0)
  {
    fprintf(stderr, "Failed to send alert to hooker\n");
  }
}

static uint64_t calculate_p99(struct latency_value *latencies, int count)
{
  // Strict bounds checking
  if (count <= 0 || latencies == NULL)
  {
    return 0;
  }

  // For small sample sizes, just return the maximum
  uint64_t max_duration = latencies[0].duration;

  // If only one sample, return it
  if (count == 1)
  {
    return max_duration;
  }

  // For multiple samples, find the maximum
  for (int i = 1; i < count && i < MAX_ENTRIES; i++)
  {
    if (latencies[i].duration > max_duration)
    {
      max_duration = latencies[i].duration;
    }
  }

  // If less than 100 samples, return the maximum
  if (count < 100)
  {
    return max_duration;
  }

  // For larger sample sizes, do proper P99 calculation
  // Simple bubble sort for demonstration
  int sort_count = count < MAX_ENTRIES ? count : MAX_ENTRIES;
  for (int i = 0; i < sort_count - 1; i++)
  {
    for (int j = 0; j < sort_count - i - 1; j++)
    {
      if (latencies[j].duration > latencies[j + 1].duration)
      {
        struct latency_value temp = latencies[j];
        latencies[j] = latencies[j + 1];
        latencies[j + 1] = temp;
      }
    }
  }

  // Calculate P99 index safely
  sort_count = count < MAX_ENTRIES ? count : MAX_ENTRIES;
  int p99_index = (sort_count * 99) / 100; // More precise P99 calculation
  if (p99_index < 0)
  {
    p99_index = 0;
  }
  if (p99_index >= sort_count)
  {
    p99_index = sort_count - 1;
  }

  return latencies[p99_index].duration;
}

static int add_client(int sock)
{
  pthread_mutex_lock(&clients_mutex);

  if (client_count >= MAX_CLIENTS)
  {
    pthread_mutex_unlock(&clients_mutex);
    return -1; // 数组已满
  }

  client_sockets[client_count++] = sock;
  int index = client_count - 1; // 记住索引位置
  printf("add_client: %d\n", index);

  pthread_mutex_unlock(&clients_mutex);
  return index;
}

static void remove_client(int index)
{
  pthread_mutex_lock(&clients_mutex);

  if (index < client_count - 1)
  {
    // 移动最后一个客户端到这个位置
    client_sockets[index] = client_sockets[client_count - 1];
  }
  client_count--;

  pthread_mutex_unlock(&clients_mutex);
}

int main(int argc, char **argv) {
    // Set up signals
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    bool is_hooker = (argc > 1) && atoi(argv[1]);
    printf("is_hooker: %d\n", is_hooker);

    // Create and bind + listen
    server_sock = setup_hooker_server(); // Now `server_sock` is a global, or you keep it local but pass to the thread
    if (server_sock < 0) {
        fprintf(stderr, "Failed to set up hooker server\n");
        return 1;
    }

    // Start thread that does the infinite accept loop
    pthread_t hooker_thread;
    pthread_create(&hooker_thread, NULL, hooker_thread_func, &server_sock);

    // If you want to connect to other IPs when is_hooker==true, do so here:
    if (is_hooker) {
        for (int i = 0; i < atoi(argv[1]); i++) {
            struct sockaddr_in server_addr2;
            memset(&server_addr2, 0, sizeof(server_addr2));
            server_addr2.sin_family = AF_INET;
            server_addr2.sin_port = htons(HOOKER_PORT);
            if (inet_pton(AF_INET, argv[2 + i], &server_addr2.sin_addr) <= 0) {
                perror("inet_pton");
                continue;
            }

            // Create a *new* socket for connecting out
            int connector_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (connector_fd < 0) {
                perror("socket");
                continue;
            }

            if (connect(connector_fd, (struct sockaddr *)&server_addr2, sizeof(server_addr2)) < 0) {
                perror("connect");
                close(connector_fd);
            } else {
                printf("Connected to %s!\n", argv[2 + i]);
                // Possibly store 'connector_fd' somewhere if you need it.
            }
        }
    }

    // Now proceed with loading BPF, attaching probes, etc.
    skel = uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
    }

    int err = uprobe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    printf("Successfully attached all probes\n");

    bpf_object_skel bpf_obj = (bpf_object_skel)(uintptr_t)skel->obj;
    int map_fd = bpf_map__fd(skel->maps.latency_map);
    printf("Successfully loaded BPF program and got map fd: %d\n", map_fd);

    // Main loop for reading the map
    struct latency_value latencies[MAX_ENTRIES];
    while (!should_exit) {
        struct latency_key key = {}, next_key = {};
        struct latency_value value;
        int latency_count = 0;

        // Pull all entries
        while (wasm_bpf_map_operate(map_fd, BPF_MAP_GET_NEXT_KEY, &key, NULL, &next_key, 0) == 0) {
            if (wasm_bpf_map_operate(map_fd, BPF_MAP_LOOKUP_ELEM, &next_key, &value, NULL, 0) == 0) {
                if (latency_count < MAX_ENTRIES) {
                    latencies[latency_count++] = value;
                }
                // Check for immediate tail latency
                if (value.duration > LATENCY_THRESHOLD_MS * 1000000ULL) {
                    printf("Tail latency detected in %s (PID: %u) - Duration: %lu ms\n",
                           value.comm, next_key.pid, value.duration / 1000000ULL);
                    send_alert_to_hooker(hooker_sock, &next_key, &value);
                }
                // Delete the processed entry
                wasm_bpf_map_operate(map_fd, BPF_MAP_DELETE_ELEM, &next_key, NULL, NULL, 0);
            }
            key = next_key;
        }

        // Calculate and report P99
        if (latency_count > 0) {
            uint64_t p99 = calculate_p99(latencies, latency_count);
            // printf("P99 latency: %lu ms (from %d samples)\n", p99 / 1000000ULL, latency_count);
            if (p99 > P99_THRESHOLD) {
                printf("Warning: P99 latency exceeds threshold!\n");
            }
        }
    }

cleanup:
    printf("\nCleaning up...\n");
    if (skel) {
        uprobe_bpf__destroy(skel);
    }

    // Optionally wait for the hooker_thread
    pthread_join(hooker_thread, NULL);
    return 0;
}
