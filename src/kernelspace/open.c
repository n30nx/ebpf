#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

#include "../../include/common/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ARGSIZE * 1024);
} events SEC(".maps");

struct open_info {
    __u16 common_type;                 // offset:0;       size:2; signed:0;
    __u8 common_flags;                 // offset:2;       size:1; signed:0;
    __u8 common_preempt_count;         // offset:3;       size:1; signed:0;
    __s32 common_pid;                  // offset:4;       size:4; signed:1;
    __s32 syscall_nr;                  // offset:8;       size:4; signed:1;

    const __u8 *filename;              // offset:24;      size:8; signed:0;
    __u64 flags;                       // offset:32;      size:8; signed:0;
    umode_t mode;                      // offset:40;      size:8; signed:0;
};

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct open_info *ctx) {
    struct open_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // event->timestamp = bpf_ktime_get_ns();
    // bpf_printk("ts: %llu, %llu", event->timestamp, bpf_ktime_get_ns());
    event->pid = id;
    event->tgid = id >> 32;
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->filename);
    event->flags = ctx->flags;
    event->mode = ctx->mode;

    // debug
    // bpf_printk("open: %s\n", ctx->filename);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
