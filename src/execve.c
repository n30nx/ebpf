#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

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

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
{                                                       \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
}

SEC("tracepoint/syscalls/sys_enter_execve")
__s32 bpf_prog_sys_enter_execve(struct exec_info *ctx)
{
    __u16 i;
    __s32 ret;
    __u8 data[256];
    const __u8 *ptr;

    if (ctx == NULL) {
        bpf_printk("ERR");
        return 1;
    }
    if (ctx->filename == NULL) {
        bpf_printk("ERR");
        return 1;
    }

    __s32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID: %d, execve(%s, ", pid, ctx->filename);

    for (i = 0; i < 128; i++) {
        ret = bpf_probe_read_user(&ptr, sizeof(ptr), &ctx->argv[i]);
        if (ret || !ptr) {
            bpf_printk("goto envp;");
            break;
        }

        ret = bpf_probe_read_user_str(data, sizeof(data), ptr);
        if (ret < 0) {
            break;
        }

        bpf_printk("argv[%d] = %s", i, data);
    }

    for (i = 0; i < 128; i++) {
        ret = bpf_probe_read_user(&ptr, sizeof(ptr), &ctx->envp[i]);
        if (ret || !ptr) {
            bpf_printk("goto envp;");
            break;
        }

        ret = bpf_probe_read_user_str(data, sizeof(data), ptr);
        if (ret < 0) {
            break;
        }

        bpf_printk("envp[%d] = %s", i, data);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
