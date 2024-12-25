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

struct iov_data {
    size_t len;
    void *base;
    void *body_start;
};

#endif // _SHADOW_H