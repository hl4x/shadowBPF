#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "shadow.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct shadow_bpf *skel; // double check when skeleton file is created
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* cleaner handling of ctrl+c */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* load and verify BPF programs */
    skel = shadow_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        goto cleanup;
    }

    /* attach kprobes */
    err = shadow_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started!\n"); 

    while (!exiting) {
        sleep(1);
    }

    cleanup:
        shadow_bpf__destroy(skel);
        return -err;
}