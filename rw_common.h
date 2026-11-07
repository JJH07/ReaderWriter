#ifndef RW_COMMON_H
#define RW_COMMON_H

#include <stdint.h>
#include <sys/un.h>

#define RW_PATH_MAX 4096
#define RW_DEFAULT_SOCKET "./tmp/readerwriter.sock"
#define RW_MAGIC UINT32_C(0x52573131)

/* Local, same-build protocol. SOCK_SEQPACKET preserves each packet boundary. */
struct rw_request {
    uint32_t magic;
    char path[RW_PATH_MAX];
};

enum rw_status {
    RW_GRANTED = 1,
    RW_QUEUED,
    RW_BUSY,
    RW_INVALID,
    RW_SHUTDOWN,
    RW_DONE
};

int rw_send_status(int fd, enum rw_status status);
int rw_address(const char *path, struct sockaddr_un *address);
int rw_absolute(const char *path, char *out, unsigned long size);
int rw_copy(int source, int destination);
int rw_number(const char *text, long minimum, long maximum, long *result);

#endif
