#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int fd = open("/etc/hostname", O_RDONLY);
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);

    open("/does/not/exist", O_RDONLY);   /* fails with ENOENT */

    write(1, "read ", 5);
    printf("%zd bytes\n", n);
    return 0;
}
