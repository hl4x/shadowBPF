#include "vmlinux.h"
#include "shadow.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ringbuf map to pass messages between kernel and user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ENTRIES);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct iov_data);
} iov_data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct data_start_end);
} data_start_end_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

static int cmp_sun_path(const char *sun_path)
{
    static const char path[] = "/run/docker.sock";
    if (!bpf_strncmp(sun_path, sizeof(path), &path)) { 
        /* match */
        return 1;
    }
    return 0;
}

static int is_docker_sock(struct socket *sock)
{
    /* read sun_path */
    char sun_path[UNIX_PATH_MAX] = { 0 };
    struct unix_sock *us = (struct unix_sock *)BPF_CORE_READ(sock, sk);
    char *addr = (char *)BPF_CORE_READ(us, addr);
    bpf_probe_read_kernel(&sun_path, UNIX_PATH_MAX, addr + SOCK_PATH_OFFSET); 

    /* check if sun_path is /run/docker.sock */    
    if (!cmp_sun_path(&sun_path)) {
        /* no match */
        return 0; 
    }   
    /* match */
    return 1;
}

/*
Inspect container:
'docker ps' : GET /v1.47/containers/json
'docker ps -a' :  GET /v1.47/containers/json?all=1
'docker inspect crazy_mclean' : GET /v1.47/containers/crazy_mclean/json
'docker ps -n 1' : GET /v1.47/containers/json?limit=1 => show lastest contianer, same as 'docker ps -l'

Create container:
'docker run --rm -it alpine' : POST /v1.47/containers/create

Pull container:
'docker pull alpine' : POST /v1.47/images/create?fromImage=alpine&tag=latest
'docker image pull myregistry.local:5000/testing/test-image' : POST /v1.47/images/create?fromImage=myregistry.local%3A5000%2Ftesting%2Ftest-image&tag=latest

Kill container:
'docker kill crazy_mclean' : POST /v1.47/containers/crazy_mclean/kill

*/

// SEC("fentry/unix_stream_recvmsg")
// int BPF_PROG(unix_stream_recvmsg, struct socket *sock, struct msghdr *msg,
//                     size_t size, int flags)
// {
//     size_t pid_tgid = bpf_get_current_pid_tgid();

//     /* exit if socket is not /run/docker.sock */
//     if (!is_docker_sock(sock))
//         return 0;
    
//     struct iov_data data = {
//         .len = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len), /* msg->msg_iter.__ubuf_iovec.iov_len */
//         .base = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base), /* msg->msg_iter.__ubuf_iovec.iov_base */
//     };
//     bpf_printk("RECEIVED LEN: %d", data.len);
//     bpf_printk("RECEIVED DATA: %s", data.base);
    
//     char nuke[64] = { 0 };
//     bpf_probe_read_kernel(nuke, data.len, (void*)0xffff6000);
//     bpf_probe_write_user(data.base, nuke, sizeof(nuke));

//     bpf_printk("NEW DATA: %s", BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base));
//     // bpf_map_update_elem(&iov_data_map, &pid_tgid, &data, BPF_ANY);

//     bpf_printk("SANITY");
//     return 0;
// }

// SEC("fmod_ret/ksys_read")
// int BPF_PROG(ksys_read, unsigned int fd, char __user *buf, size_t count)
// {
//     size_t pid_tgid = bpf_get_current_pid_tgid();
//     struct iov_data *data = bpf_map_lookup_elem(&iov_data_map, &pid_tgid);
//     if (!data) {
//         bpf_printk("NO ADA");
//         return 0;
//     }   
//     //bpf_probe_read_kernel(buf, count, 0); //hopefully memset 0 on err
// 	return 0;
// }


SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(unix_stream_sendmsg, struct socket *sock, struct msghdr *msg,
			        size_t len, int ret)
// int unix_stream_sendmsg(struct pt_regs *ctx)
{
   size_t pid_tgid = bpf_get_current_pid_tgid();

    /* exit if socket is not /run/docker.sock */
    if (!is_docker_sock(sock))
        return 0;

    /* docker seems to only use ITER_UBUF so just read __ubuf_iovec */
    struct iov_data data = {
        .len = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len), /* msg->msg_iter.__ubuf_iovec.iov_len */
        .base = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base), /* msg->msg_iter.__ubuf_iovec.iov_base */
    };

    if ((s64)data.len <= 0 || data.len >= BPF_MAX_VAR_SIZ)
        return 0;

    bpf_map_update_elem(&iov_data_map, &pid_tgid, &data, BPF_ANY); /* save for later :) */
    // bpf_printk("RECEIVED LEN: %d", data.len);
    // bpf_printk("RECEIVED DATA: %s", data.base);

    bpf_tail_call(ctx, &map_prog_array, PROG_01);
    return 0;
}

// PROG_01
SEC("fentry/unix_stream_sendmsg")
int http_find_msg_body_start(void *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    struct iov_data *data = bpf_map_lookup_elem(&iov_data_map, &pid_tgid);
    if (!data)
        return 0;

    struct data_start_end data_start_end = { 0 };
    char local_buf[LOCAL_BUF_SIZE] = { 0 };
    /* loop and find the start of our message body if anything in it exists */
    for (u32 i = 0; i < LOOP_SIZE; i++) {
        bpf_probe_read(&local_buf, sizeof(local_buf), data->base);
        for (u32 j = 0; j < LOCAL_BUF_SIZE; j++) { 
            if (local_buf[j] == '[') {
                data_start_end.start = data->base + j;
                goto out;
            }
        }
        data->base += LOCAL_BUF_SIZE;
    }

out:
    /* only add to map if not a match; 0 == match for bpf_strncmp */
    bpf_probe_read(&local_buf, sizeof(local_buf), data_start_end.start);
    if (local_buf[0] == '[' && local_buf[1] == ']')
        return 0;
    if (data_start_end.start) {
        bpf_map_update_elem(&data_start_end_map, &pid_tgid, &data_start_end, BPF_ANY);
        bpf_printk("START ADDR: %s", data_start_end.start);
        //TODO: tail call here to find end using data.base + data.len and working backwards
    }
    return 0;
}

char _license[] SEC("license") = "GPL";