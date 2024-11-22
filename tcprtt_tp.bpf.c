#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tcprtt.h"

#include "bpf_tracing_net.h"

// TODO: define ring buffer
// TODO: define hash map

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // handle ipv4 only
    if (ctx->family != AF_INET)
        return 0;
    
    // TODO: complete kernel program
    return 0;
}