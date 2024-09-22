#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define UNIX_PATH_MAX 108
#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

char _license[] SEC("license") = "GPL";

struct iov_data {
    size_t len;
    void *base;
};

static int cmp_sun_path(const char *sun_path)
{
    static const char path[] = "/run/docker.sock";
    if (!bpf_strncmp(sun_path, sizeof(path), &path)) { 
        /* match */
        return 1;
    }
    return 0;
}

SEC("kprobe/unix_stream_sendmsg")
int BPF_KPROBE(unix_stream_sendmsg, struct socket *sock, struct msghdr *msg,
			       size_t len)
{
    char sun_path[UNIX_PATH_MAX] = { 0 };

    /* read sun_path */
    struct unix_sock *us = (struct unix_sock *)BPF_CORE_READ(sock, sk);
    char *addr = (char *)BPF_CORE_READ(us, addr);
    bpf_probe_read_kernel(&sun_path, UNIX_PATH_MAX, addr + SOCK_PATH_OFFSET); 

    /* check if sun_path is /run/docker.sock */    
    if (!cmp_sun_path(&sun_path))
        return 0;
    bpf_printk("Matched: %s", &sun_path);

    /* docker seems to only use ITER_UBUF so just read __ubuf_iovec */
    struct iov_data data;
    data.len = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len);
    data.base = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
    bpf_printk("%s %d", data.base, data.len);

    return 0;
}