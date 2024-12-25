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

#define PAGE_SIZE 4096
#define MAP_ADDR 0xb0000

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
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    if ((signal(SIGTERM, sig_handler)) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
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
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Increase RLIMIT_MEMLOCK to allow bpf sub-system to do anything */
    if (!bump_memlock_rlimit())
        return false;

    /* Setup signal handler so we exit cleanly */
    if (!setup_sig_handler())
        return false;

    return true;
}

static int retard_time(void *base, size_t len)
{
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd == -1)
        return 0;
    char *retard = mmap(base, len, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, 0);
    if (!retard) {
        perror("mmap");
        return 0;
    }
    fprintf(stderr, "Retard located: %p\n", retard);
    
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    if (e && e->base && e->len) {
        fprintf(stderr, "Found data: %p\n", e->base);
        retard_time(e->base, e->len);
    } else {
        fprintf(stderr, "Invalid event!\n");
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct shadow_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    /* Do common setup */
    if (!setup())
        exit(EXIT_FAILURE);

    /* Open BPF applications */
    skel = shadow_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Load and verify BPF program */
    err = shadow_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Add program to map to call it later */
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

    /* Attach kprobes */
    err = shadow_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started!\n"); 

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer!\n");
        goto cleanup;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    shadow_bpf__destroy(skel);
    return -err;
}