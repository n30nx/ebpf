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
// #include <xdp/libxdp.h>

#include "include/common/common.h"
#include "include/userspace/json.h"
#include "include/userspace/filter.h"

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

#define BPF_COUNT 2

filter_t *filter;
filter_t *open_filter;
FILE *fp_execve;
FILE *fp_open;

struct bpf_object *b_obj[BPF_COUNT];
struct bpf_link *b_link[BPF_COUNT];
struct ring_buffer *b_rb[BPF_COUNT];

pthread_mutex_t file_lock;

static int handle_execve(void *ctx, void *data, size_t data_sz) {
    struct execve_event *event = (struct execve_event *)data;
    //printf("8\n");
    if (data_sz < sizeof(struct execve_event)) {
        fprintf(stderr, "Invalid event size\n");
        return 0; // Continue polling
    }

    /*int s = 0;
    do {
        if (pthread_mutex_trylock(&file_lock) != 0) {
            if (errno == EBUSY) asm("nop");
            else if (errno == EAGAIN) fprintf(stderr, "fail\n");
            else if (errno == EINVAL) fprintf(stderr, "invalid mutex\n");
            else break;
        } else {
            break;
        }
        printf("errno=%d: Waiting the mutex to unlock on handle_execve for %d seconds\n", errno, s++);
        sleep(1);
    } while (1);*/
    int i;
    for (i = 0; i < LOOP_MAX; i++) {
        //printf("9\n");
        if (event->envp[i][0] == 0) break;
        //printf("10\n");
        if (filter != NULL) {
            //printf("11\n");
            const char *res = filter_data(event->envp[i], filter);
            //printf("12\n");
            if (res != event->envp[i]) return 0;
        }
    }

    //printf("13\n");
    
    printf("PID: %u TGID: %u Command: %s Filename: %s Syscall: %d\n", event->pid, event->tgid, event->comm, event->filename, event->syscall_nr);
    
    //printf("14\n");
    write_json_execve(fp_execve, event);

    //printf("15\n");
    fprintf(fp_execve, ",");
    
    //printf("16\n");
    /*if (pthread_mutex_unlock(&file_lock) != 0) {
        fprintf(stderr, "Failed to unlock mutex on handle_execve\n");
        return 1;
    }*/

    return 0;
}

static int handle_open(void *ctx, void *data, size_t data_sz) {
    struct open_event *event = (struct open_event *)data;
    //printf("1\n");
    if (data_sz < sizeof(struct open_event)) {
        fprintf(stderr, "Invalid event size\n");
        return 1;
    }
    //printf("2\n");
    /*if (pthread_mutex_lock(&file_lock) != 0) {
        fprintf(stderr, "Failed to lock mutex on handle_open\n");
        return 1;
    }*/

    //printf("3\n");
    time_t ti = time(NULL);
    const char *res = filter_data_exact(event->filename, open_filter);
    if (res != event->filename) return 1;

    res = filter_data(event->filename, open_filter);
    if (res != event->filename) return 1;
    // printf("elapsed: %lu\n", time(NULL) - ti);
    //printf("4\n");

    printf("PID: %d TGID: %u Flags: %llu Mode: %d Filename: %s\n", event->pid, event->tgid, event->flags, event->mode, event->filename);
    write_json_open(fp_open, event);
    fprintf(fp_open, ",");
    
    //printf("7\n");
    /*if (pthread_mutex_unlock(&file_lock) != 0) {
        fprintf(stderr, "Failed to unlock mutex on handle_open\n");
        return 1;
    }*/

    return 0;
}

/*
static int handle_network(void *ctx, void *data, size_t data_sz) {
    struct net_event *event = (struct net_event *)data;
    
    if (data_sz < sizeof(struct net_event)) {
        fprintf(stderr, "Invalid event size\n");
        return 0; // Continue polling
    }

    char saddr_str[INET6_ADDRSTRLEN];
    char daddr_str[INET6_ADDRSTRLEN];

    if (event->family == AF_INET) {
        inet_ntop(AF_INET, event->saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET, event->daddr, daddr_str, sizeof(daddr_str));
    } else if (event->family == AF_INET6) {
        inet_ntop(AF_INET6, event->saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET6, event->daddr, daddr_str, sizeof(daddr_str));
    } else {
        fprintf(stderr, "Unknown address family\n");
        return 0; // Continue polling
    }

    pthread_mutex_lock(&file_lock);

    // write_json_network(fp, event);

    printf("PID: %u TGID: %u Protocol: %u SAddr: %s DAddr: %s DPort: %u\n",
           event->pid, event->tgid, event->protocol, saddr_str, daddr_str, ntohs(event->dport));

    //fprintf(fp, ",");

    pthread_mutex_unlock(&file_lock);

    return 0;
}
*/

void signal_handler(int signum) {
    // pthread_mutex_lock(&file_lock);
    fseek(fp_execve, ftell(fp_execve) - 1, SEEK_SET);
    fprintf(fp_execve, "]");
    fclose(fp_execve);

    fseek(fp_open, ftell(fp_open) - 1, SEEK_SET);
    fprintf(fp_open, "]");
    fclose(fp_open);
    // pthread_mutex_unlock(&file_lock);

    free_filter(filter);
    free_filter(open_filter);

    pthread_mutex_destroy(&file_lock);

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

/*static int load_xdp_program(const char *restrict filename, const char *restrict iface, int (*function)(void *ctx, void *data, size_t data_sz), int i) {
    struct bpf_program *prog;
    int prog_fd, err, map_fd;
    int ifindex = if_nametoindex(iface);

    struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char fn[] = "network.o";
	char pn[] = "loader";
	struct xdp_program *xprog;
	char errmsg[1024];
	// int prog_fd, err; // = EXIT_SUCCESS;

	struct config cfg = {
		.attach_mode = XDP_MODE_UNSPEC,
		.ifindex   = ifindex,
		.do_unload = false,
	};

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                            .open_filename = fn,
                            .prog_name = pn,
                            .opts = &bpf_opts);

    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index for %s\n", iface);
        return 1;
    }

    xprog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(xprog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		return 1;
	}

    err = xdp_program__attach(xprog, ifindex, XDP_MODE_UNSPEC, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		return 1;
	}


    prog_fd = xdp_program__fd(xprog);
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return 1;
	}

    b_obj[i] = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(b_obj[i])) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", filename);
        return 1;
    }

    err = bpf_object__load(b_obj[i]);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        return 1;
    }

    prog = bpf_object__find_program_by_name(b_obj[i], "xdp");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program in object\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);

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

    // Attach the XDP program
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        return 1;
    }

    while (true) {
        ring_buffer__poll(b_rb[i], -1);
    }

    return 0;
}*/

void *poll_ring_buffer(void *arg) {
    struct ring_buffer *rb = (struct ring_buffer*)arg;
    // printf("%p\n", rb);
    // printf("Started polling ring buffer %d\n", index);
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
    /*res = load_xdp_program("network.o", "enp2s0", handle_network, 4);
    if (res == 1) {
        printf("Error loading network.o\n");
        return 1;
    }*/


    open_filter = read_config("open.conf");

    if (argc >= 3) {
        filter = read_config(argv[2]);
    }

    filename = (char*)malloc(sizeof(char) * (strlen(argv[1]) + 128));
    sprintf(filename, "open-%s", argv[1]);

    fp_open = fopen(filename, "w+");
    assert(fp_open);
    fprintf(fp_open, "[");

    memset(filename, 0, sizeof(char) * (strlen(argv[1]) + 128));

    sprintf(filename, "execve-%s", argv[1]);

    fp_execve = fopen(filename, "w+");
    assert(fp_execve);
    fprintf(fp_execve, "[");

    free(filename);

    signal(SIGINT, signal_handler);
    
	if (pthread_mutex_init(&file_lock, NULL) != 0) {
		printf("Error while initializing the arr_lock\n");
	}

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
