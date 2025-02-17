#ifndef SHADOW_H
#define SHADOW_H

#define PROG_00 0
#define PROG_01 1
#define PROG_02 2
#define PROG_03 3
#define PROG_04 4

#define UNIX_PATH_MAX 108
#define MAX_ENTRIES 256 * 1024
#define BPF_MAX_VAR_SIZ (1<<29)
#define LOCAL_BUF_SIZE 32
#define LOOP_SIZE 32  
#define MAX_PID_LEN 16
#define MAX_ENVP_SIZE 24

#define LD_PRELOAD_MAX_LEN 300 

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

struct iov_data {
    size_t len;
    void *base;
    void *body_start;
};

struct event {
    bool success;
};

#endif // SHADOW_H
