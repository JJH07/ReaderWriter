#define _GNU_SOURCE
#include "rw_common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int rw_send_status(int fd, enum rw_status status)
{
    uint32_t packet = (uint32_t)status;
    ssize_t sent;
    do {
        sent = send(fd, &packet, sizeof(packet), MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)sizeof(packet) ? 0 : -1;
}

int rw_address(const char *path, struct sockaddr_un *address)
{
    if (strlen(path) >= sizeof(address->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, strlen(path) + 1);
    return 0;
}

int rw_absolute(const char *path, char *out, unsigned long size)
{
    char cwd[RW_PATH_MAX];
    int length;
    if (path[0] == '/') {
        length = snprintf(out, size, "%s", path);
    } else {
        if (getcwd(cwd, sizeof(cwd)) == NULL)
            return -1;
        length = snprintf(out, size, "%s/%s", cwd, path);
    }
    if (length < 0 || (unsigned long)length >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

int rw_copy(int source, int destination)
{
    char buffer[8192];
    for (;;) {
        ssize_t count = read(source, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (count == 0)
            return 0;
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(destination, buffer + offset,
                                    (size_t)(count - offset));
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0)
                return -1;
            offset += written;
        }
    }
}

int rw_number(const char *text, long minimum, long maximum, long *result)
{
    char *end;
    errno = 0;
    long number = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        number < minimum || number > maximum)
        return -1;
    *result = number;
    return 0;
}
