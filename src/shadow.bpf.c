#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/unix_stream_sendmsg")
int BPF_KPROBE(unix_stream_sendmsg, struct socket *sock, struct msghdr *msg,
			       size_t len)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE ENTRY pid = %d\n", pid);
    return 0;
}