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

int main(int argc, char **argv)
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
        bpf_map__fd(skel->maps.map_prog_array),
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

    printf("Successfully started!\n"); 

    while (!exiting)
        sleep(1);

cleanup:
    shadow_bpf__destroy(skel);
    return -err;
}