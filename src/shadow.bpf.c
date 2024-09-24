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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct iov_data);
} iov_data_map SEC(".maps");

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
    /* read sun_path */
    char sun_path[UNIX_PATH_MAX] = { 0 };
    struct unix_sock *us = (struct unix_sock *)BPF_CORE_READ(sock, sk);
    char *addr = (char *)BPF_CORE_READ(us, addr);
    bpf_probe_read_kernel(&sun_path, UNIX_PATH_MAX, addr + SOCK_PATH_OFFSET); 

    /* check if sun_path is /run/docker.sock */    
    if (!cmp_sun_path(&sun_path))
        return 0;

    /* docker seems to only use ITER_UBUF so just read __ubuf_iovec */
    struct iov_data data;
    data.len = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len);
    data.base = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
    bpf_printk("%s %d", data.base, data.len);

    char overwrite[] = "        ";
    #pragma unroll
    for (u32 i = 0; i < 8*5; i += 8)
        bpf_probe_write_user((u64 *)&data.base[i], (u64 *)overwrite, sizeof(overwrite));
    
    return 0;
}