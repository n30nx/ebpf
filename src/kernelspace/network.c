#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include "../../include/common/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    struct net_event *event;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    event->pid = bpf_get_current_pid_tgid();
    event->tgid = event->pid >> 32;
    event->protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(event, 0);
            return XDP_PASS;
        }

        event->sport = tcp->source;
        event->dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            bpf_ringbuf_discard(event, 0);
            return XDP_PASS;
        }

        event->sport = udp->source;
        event->dport = udp->dest;
    }

    bpf_probe_read_kernel(&event->saddr, sizeof(event->saddr), &ip->saddr);
    bpf_probe_read_kernel(&event->daddr, sizeof(event->daddr), &ip->daddr);

    bpf_ringbuf_submit(event, 0);

    return XDP_PASS;
}
