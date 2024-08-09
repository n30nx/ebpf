#include <linux/types.h>
#include <stddef.h>

#pragma once

#define LOOP_MAX 64
#define MAX_ARGSIZE 256

struct execve_event {
    __u32 pid;
    __u32 tgid;
    __s32 syscall_nr;
    char comm[16];
    char filename[MAX_ARGSIZE];
    char argv[LOOP_MAX][MAX_ARGSIZE];
    char envp[LOOP_MAX][MAX_ARGSIZE];
};

const size_t arrlen(const char argv[LOOP_MAX][MAX_ARGSIZE]);
