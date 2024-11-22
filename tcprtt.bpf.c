#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// for the definition of the type shared between user and kernel
#include "tcprtt.h"

#include "bpf_tracing_net.h"
    
// TODO: define ring buffer

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk /*, optional */)
{
    // handler ipv4 only
    if (sk->__sk_common.skc_family != AF_INET)
        return 0;
    
    // TODO: complete kernel program
    return 0;
}