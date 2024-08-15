#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

#include "../../include/common/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ARGSIZE * 1024);
} events SEC(".maps");

struct exec_info {
    __u16 common_type;            // Offset=0, size=2
    __u8  common_flags;           // Offset=2, size=1
    __u8  common_preempt_count;   // Offset=3, size=1
    __s32 common_pid;             // Offset=4, size=4

    __s32 syscall_nr;             // Offset=8, size=4
    __u32 pad;                    // Offset=12, size=4 (padding)
    const __u8 *filename;         // Offset=16, size=8 (pointer)
    const __u8 *const *argv;      // Offset=24, size=8 (pointer)
    const __u8 *const *envp;      // Offset=32, size=8 (pointer)
};

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct exec_info *ctx) {
    struct execve_event *event;
    const __u8 *ptr;
    int ret;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();

    event->timestamp = bpf_ktime_get_ns();
    event->pid = id;
    event->tgid = id >> 32;
    event->syscall_nr = ctx->syscall_nr;

    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->filename);
    
    int i;

    #pragma unroll
    for (i = 0; i < LOOP_MAX; i++) {
        ret = bpf_probe_read_user(&ptr, sizeof(ptr), &ctx->argv[i]);
        if (ret < 0 || !ptr) {
            event->argv_len = i;
            event->argv[i][0] = 0;
            break;
        }

        ret = bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]), ptr);
        if (ret < 0) {
            event->argv_len = i;
            event->argv[i][0] = 0;
            break;
        }
    }

    #pragma unroll
    for (i = 0; i < LOOP_MAX; i++) {
        ret = bpf_probe_read_user(&ptr, sizeof(ptr), &ctx->envp[i]);
        if (ret < 0 || !ptr) {
            event->envp_len = i;
            event->envp[i][0] = 0;
            break;
        }

        ret = bpf_probe_read_user_str(event->envp[i], sizeof(event->envp[i]), ptr);
        if (ret < 0) {
            event->envp_len = i;
            event->envp[i][0] = 0;
            break;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
