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

#define MAX_BPF_INSTRUCTIONS 4096

int load_bpf_file(char *filename) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int fd;

    // Load the object file
    obj = bpf_object__open(filename);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return -1;
    }

    // Load and verify the program
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return -1;
    }

    // Attach program
    prog = bpf_object__find_program_by_name(obj, "bpf_prog_sys_enter_execve");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program in object\n");
        return -1;
    }

    link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return -1;
    }

    printf("eBPF program loaded and attached successfully\n");

    // Keeping the program running to listen to tracepoints
    printf("Press CTRL+C to stop\n");
    sleep(-1);

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <EBPF_PROGRAM.o>\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];

    // Increase resource limits
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    return load_bpf_file(filename);
}
