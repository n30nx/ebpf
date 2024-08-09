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
#include <sys/resource.h>

#include "include/common/common.h"
#include "include/userspace/json.h"
#include "include/userspace/filter.h"

filter_t *filter;
char *filename;
FILE *fp;

struct bpf_object *b_obj;
struct bpf_link *b_link;
struct ring_buffer *b_rb;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct execve_event *event = (struct execve_event *)data;

    if (data_sz < sizeof(struct execve_event)) {
        fprintf(stderr, "Invalid event size\n");
        return 0; // Continue polling
    }

    int i;
    for (i = 0; i < LOOP_MAX; i++) {
        if (event->envp[i][0] == 0) break;
        if (filter != NULL) {
            const char *res = filter_data(event->envp[i], filter);
            if (res != event->envp[i]) return 0;
        }
    }

    /*for (i = 0; i < LOOP_MAX; i++) {
        if (event->argv[i][0] == 0) break;
        printf("argv[%d] = %s\n", i, event->argv[i]);
    }

    for (i = 0; i < LOOP_MAX; i++) {
        if (event->envp[i][0] == 0) break;
        printf("envp[%d] = %s\n", i, event->envp[i]);
    }*/

    write_json(fp, event);

    printf("PID: %u TGID: %u Command: %s Filename: %s Syscall: %d\n", event->pid, event->tgid, event->comm, event->filename, event->syscall_nr);

    fprintf(fp, ",");

    return 0;
}

/*void cleanup_function(void) {
    fseek(fp, ftell(fp) - 1, SEEK_SET);
    fprintf(fp, "]");
    fclose(fp);

    free_filter(filter);

    ring_buffer__free(b_rb);
    bpf_link__destroy(b_link);
    bpf_object__close(b_obj);
}*/

void signal_handler(int signum) {
    fseek(fp, ftell(fp) - 1, SEEK_SET);
    fprintf(fp, "]");
    fclose(fp);

    free_filter(filter);

    ring_buffer__free(b_rb);
    bpf_link__destroy(b_link);
    bpf_object__close(b_obj);

    exit(0);
}

int main(int argc, char **argv) {
    struct bpf_program *prog;
    int map_fd;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <EBPF_PROGRAM.o> <LOG_FILE> <CONFIG_FILE (optional)>\n", argv[0]);
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    b_obj = bpf_object__open(argv[1]);
    if (libbpf_get_error(b_obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(b_obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(b_obj, "sys_enter_execve");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    b_link = bpf_program__attach(prog);
    if (libbpf_get_error(b_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(b_obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find BPF map\n");
        return 1;
    }

    b_rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!b_rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    filename = argv[2];
    fp = fopen(filename, "w");

    if (argc >= 4) {
        filter = read_config(argv[3]);
    }

    fprintf(fp, "[");

    signal(SIGINT, signal_handler);
    
    printf("Successfully started, press Ctrl+C to stop.\n");
    while (true) {
        ring_buffer__poll(b_rb, -1);
    }

    return 0;
}
