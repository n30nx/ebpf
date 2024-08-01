#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <sys/resource.h>

#define LOOP_MAX 32

// TODO:
// make output json
// add filtering mechanism

struct execve_event {
    __u32 pid;
    __u32 tgid;
    __s32 syscall_nr;
    char comm[16];
    char filename[256]; 
    char argv[32][256];
    char envp[32][256];
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct execve_event *event = (struct execve_event *)data;

    if (data_sz < sizeof(struct execve_event)) {
        fprintf(stderr, "Invalid event size\n");
        return 0; // Continue polling
    }

    printf("PID: %u TGID: %u Command: %s Filename: %s\n", event->pid, event->tgid, event->comm, event->filename);

    int i;
    #pragma unroll
    for (i = 0; i < LOOP_MAX; i++) {
        if (event->argv[i][0] == 0) break;
        printf("argv[%d] = %s\n", i, event->argv[i]);
    }

    #pragma unroll
    for (i = 0; i < LOOP_MAX; i++) {
        if (event->envp[i][0] == 0) break;
        printf("envp[%d] = %s\n", i, event->envp[i]);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb;
    int map_fd;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <EBPF_PROGRAM.o>\n", argv[0]);
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    obj = bpf_object__open(argv[1]);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "sys_enter_execve");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find BPF map\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Successfully started, press Ctrl+C to stop.\n");
    while (true) {
        ring_buffer__poll(rb, -1);
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
