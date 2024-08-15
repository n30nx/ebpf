#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/resource.h>
#include <net/if.h>

#include "include/common/common.h"
#include "include/userspace/json.h"
#include "include/userspace/filter.h"

#define BPF_COUNT 2

filter_t *filter;
filter_t *open_filter;

FILE *fp;

struct bpf_object *b_obj[BPF_COUNT];
struct bpf_link *b_link[BPF_COUNT];
struct ring_buffer *b_rb[BPF_COUNT];

static int handle_execve(void *ctx, void *data, size_t data_sz) {
    struct execve_event *event = (struct execve_event *)data;
    if (data_sz < sizeof(struct execve_event)) {
        fprintf(stderr, "Invalid event size\n");
        return 0;
    }

    int i;
    for (i = 0; i < LOOP_MAX; i++) {
        if (event->envp[i][0] == 0) break;
        if (filter != NULL) {
            const char *res = filter_data(event->envp[i], filter);
            if (res != event->envp[i]) return 0;
        }
    }

    flockfile(fp);
    write_json_execve(fp, event);
    fprintf(fp, ",");
    funlockfile(fp);
    
    flockfile(stdout);
    printf("PID: %u TGID: %u Command: %s Filename: %s Syscall: %d\n", event->pid, event->tgid, event->comm, event->filename, event->syscall_nr);
    funlockfile(stdout);

    return 0;
}

static int handle_open(void *ctx, void *data, size_t data_sz) {
    struct open_event *event = (struct open_event *)data;
    if (data_sz < sizeof(struct open_event)) {
        fprintf(stderr, "Invalid event size\n");
        return 1;
    }

    time_t ti = time(NULL);
    const char *res = filter_data_exact(event->filename, open_filter);
    if (res != event->filename) return 1;

    res = filter_data(event->filename, open_filter);
    if (res != event->filename) return 1;

    flockfile(fp);
    write_json_open(fp, event);
    fprintf(fp, ",");
    funlockfile(fp);

    flockfile(stdout);
    printf("PID: %d TGID: %u Flags: %llu Mode: %d Filename: %s\n", event->pid, event->tgid, event->flags, event->mode, event->filename);
    funlockfile(stdout);

    return 0;
}

void signal_handler(int signum) {
    fseek(fp, ftell(fp) - 1, SEEK_SET);
    fprintf(fp, "]");
    fclose(fp);

    free_filter(filter);
    free_filter(open_filter);

    for (int i = 0; i < BPF_COUNT; i++) {
        ring_buffer__free(b_rb[i]);
        bpf_link__destroy(b_link[i]);
        bpf_object__close(b_obj[i]);
    }

    exit(0);
}

int load_bpf_program(const char *restrict filename, const char *restrict type, int (*function)(void *ctx, void *data, size_t data_sz), int i) {
    struct bpf_program *prog;
    int map_fd;

    b_obj[i] = bpf_object__open(filename);
    if (libbpf_get_error(b_obj[i])) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(b_obj[i])) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(b_obj[i], type);
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    b_link[i] = bpf_program__attach(prog);
    if (libbpf_get_error(b_link[i])) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(b_obj[i], "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find BPF map\n");
        return 1;
    }

    b_rb[i] = ring_buffer__new(map_fd, function, NULL, NULL);
    if (!b_rb[i]) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    return 0;
}

void *poll_ring_buffer(void *arg) {
    struct ring_buffer *rb = (struct ring_buffer*)arg;
    while (true) {
        ring_buffer__poll(rb, -1);
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct bpf_program *prog;
    pthread_t threads[BPF_COUNT];
    int thread_indices[BPF_COUNT];
    int map_fd;
    char *filename;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <LOG_FILE> <CONFIG_FILE (optional)>\n", argv[0]);
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    int res;
    res = load_bpf_program("execve.o", "sys_enter_execve", handle_execve, 0);
    if (res == 1) {
        printf("Error loading execve.o\n");
        return 1;
    }
    /*res = load_bpf_program("open.o", "sys_enter_open", handle_open, 1);
    if (res == 1) {
        printf("Error loading open.o\n");
        return 1;
    }*/
    res = load_bpf_program("openat.o", "sys_enter_openat", handle_open, 1);
    if (res == 1) {
        printf("Error loading openat.o\n");
        return 1;
    }
    /*res = load_bpf_program("openat2.o", "sys_enter_openat2", handle_open, 3);
    if (res == 1) {
        printf("Error loading openat.o\n");
        return 1;
    }*/

    open_filter = read_config("open.conf");

    if (argc >= 3) {
        filter = read_config(argv[2]);
    }

    fp = fopen(argv[1], "w+");
    assert(fp);
    fprintf(fp, "[");

    signal(SIGINT, signal_handler);

    for (int i = 0; i < BPF_COUNT; i++) {
        if (pthread_create(&threads[i], NULL, poll_ring_buffer, b_rb[i])) {
            fprintf(stderr, "Error creating thread for ring buffer %d\n", i);
            return 1;
        }
    }

    printf("Successfully started, press Ctrl+C to stop.\n");
    for (int i = 0; i < BPF_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
