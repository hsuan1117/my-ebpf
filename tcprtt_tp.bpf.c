#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tcprtt.h"

#include "bpf_tracing_net.h"

// TODO: define ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// TODO: define hash map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, const void *);
    __type(value, u64);
} last_seen SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // handle ipv4 only
    if (ctx->family != AF_INET)
        return 0;
    
    // TODO: complete kernel program
    const void *sk = ctx->skaddr;
    if (ctx->newstate == TCP_ESTABLISHED && ctx->oldstate == TCP_SYN_SENT) {
        u64 *start_ns = bpf_map_lookup_elem(&last_seen, &sk);
        if (!start_ns) return 0;

        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return 0;

        e->saddr = *((__u32 *)ctx->saddr);
        e->daddr = *((__u32 *)ctx->daddr);
        e->sport = ctx->sport;
        e->dport = ctx->dport;
        e->rtt = bpf_ktime_get_ns() - *start_ns;

        bpf_ringbuf_submit(e, 0);
    } else if (ctx->newstate == TCP_CLOSE) {
        bpf_map_delete_elem(&last_seen, &sk);
    } else {
        u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&last_seen, &sk, &now, BPF_ANY);
    }
    return 0;
}