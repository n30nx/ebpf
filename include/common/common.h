#include <linux/types.h>
#include <stddef.h>

#pragma once

typedef __u8 umode_t;

#define LOOP_MAX 64
#define MAX_ARGSIZE 256

struct execve_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __s32 syscall_nr;
    char comm[16];
    char filename[MAX_ARGSIZE];
    char argv[LOOP_MAX][MAX_ARGSIZE];
    size_t argv_len;
    char envp[LOOP_MAX][MAX_ARGSIZE];
    size_t envp_len;
};

struct open_event {
    __u64 timestamp;
    __s32 pid;
    __u32 tgid;
    __u64 flags;
    __s32 syscall_nr;
    umode_t mode;
    char filename[MAX_ARGSIZE];
};

struct net_event {
    __u64 pid;
    __u64 tgid;
    __u32 family;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 saddr[16];
    __u8 daddr[16];
};

// debug
size_t arrlen(const char argv[LOOP_MAX][MAX_ARGSIZE]);
