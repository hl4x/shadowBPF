#ifndef _SHADOW_H
#define _SHADOW_H

#define PROG_01 1

#define UNIX_PATH_MAX 108
#define MAX_ENTRIES 256 * 1024
#define BPF_MAX_VAR_SIZ (1<<29)
#define LOCAL_BUF_SIZE 32
#define LOOP_SIZE 32  

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

#if defined(__TARGET_ARCH_x86)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__x64_"
#elif defined(__TARGET_ARCH_s390)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__s390x_"
#elif defined(__TARGET_ARCH_arm64)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__arm64_"
#elif defined(__TARGET_ARCH_riscv)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__riscv_"
#else
#define SYSCALL_WRAPPER 0
#define SYS_PREFIX "__se_"
#endif

struct iov_data {
    size_t len;
    void *base;
};

struct data_start_end {
    void *start;
    void *end;
};

struct event {
    size_t len;
    void *base;
};

#endif // _SHADOW_H