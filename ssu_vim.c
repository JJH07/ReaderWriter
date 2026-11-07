#define _GNU_SOURCE
#include "rw_common.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void usage(FILE *stream)
{
    fprintf(stream, "Usage: ssu_vim FILE <-r|-w|-rw> [-t] [-s] [-d]\n"
                    "               [--socket PATH] [--timeout 1..86400]\n"
                    "EDITOR selects one executable (default: vim; no shell arguments).\n");
}

static int show_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    fflush(stdout);
    int result = rw_copy(fd, STDOUT_FILENO);
    close(fd);
    return result;
}

static void show_time(const char *label, time_t seconds)
{
    struct tm value;
    char text[32];
    if (localtime_r(&seconds, &value) != NULL &&
        strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%S", &value) != 0)
        printf("%s: %s\n", label, text);
}

static long long milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int acquire(const char *socket_path, const char *path, long timeout)
{
    struct sockaddr_un address;
    if (rw_address(socket_path, &address) < 0)
        return -1;
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct timeval io_timeout = {.tv_sec = 5, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout)) < 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        goto fail;
    struct ucred peer;
    socklen_t peer_size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) < 0 || peer.uid != geteuid()) {
        errno = EACCES;
        goto fail;
    }
    struct rw_request request = {.magic = RW_MAGIC};
    memcpy(request.path, path, strlen(path) + 1);
    ssize_t written;
    do {
        written = send(fd, &request, sizeof(request), MSG_NOSIGNAL);
    } while (written < 0 && errno == EINTR);
    if (written != (ssize_t)sizeof(request))
        goto fail;
    long long start = milliseconds();
    if (start < 0)
        goto fail;
    long long deadline = start + timeout * 1000;
    for (;;) {
        long long now = milliseconds();
        if (now < 0)
            goto fail;
        if (now >= deadline) {
            fprintf(stderr, "Timed out waiting for edit permission\n");
            errno = ETIMEDOUT;
            goto fail;
        }
        struct pollfd item = {.fd = fd, .events = POLLIN};
        int ready = poll(&item, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0)
            goto fail;
        if (ready == 0)
            continue;
        if (!(item.revents & POLLIN)) {
            errno = ECONNRESET;
            goto fail;
        }
        uint32_t status;
        ssize_t length = recv(fd, &status, sizeof(status), MSG_TRUNC);
        if (length < 0 && errno == EINTR)
            continue;
        if (length != (ssize_t)sizeof(status)) {
            errno = EPROTO;
            goto fail;
        }
        if (status == RW_GRANTED)
            return fd;
        if (status == RW_QUEUED)
            continue;
        if (status == RW_BUSY) {
            fprintf(stderr, "Edit queue is full\n");
            errno = EBUSY;
        } else if (status == RW_INVALID) {
            fprintf(stderr, "File is not managed by this daemon\n");
            errno = EINVAL;
        } else if (status == RW_SHUTDOWN) {
            fprintf(stderr, "Daemon is shutting down\n");
            errno = ECANCELED;
        } else {
            errno = EPROTO;
        }
        goto fail;
    }
fail:
    {
        int saved = errno;
        close(fd);
        errno = saved;
    }
    return -1;
}

static int wait_child(pid_t child)
{
    int status;
    pid_t result;
    do {
        result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    if (result < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int edit(const char *path, int token)
{
    const char *editor = getenv("EDITOR");
    if (editor == NULL || *editor == '\0')
        editor = "vim";
    fflush(NULL);
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        /* Keep the lease alive if the wrapper is killed while editing. */
        if (fcntl(token, F_SETFD, 0) < 0)
            _exit(126);
        execlp(editor, editor, path, (char *)NULL);
        perror("editor");
        _exit(127);
    }
    return wait_child(child);
}

static int compare(const char *before, const char *after)
{
    FILE *left = fopen(before, "rb");
    FILE *right = fopen(after, "rb");
    if (left == NULL || right == NULL) {
        if (left != NULL)
            fclose(left);
        if (right != NULL)
            fclose(right);
        return -1;
    }
    int result = 0;
    for (;;) {
        int a = fgetc(left), b = fgetc(right);
        if (ferror(left) || ferror(right)) {
            result = -1;
            break;
        }
        if (a != b) {
            result = 1;
            break;
        }
        if (a == EOF)
            break;
    }
    fclose(left);
    fclose(right);
    return result;
}

static int show_diff(const char *before, const char *after)
{
    fflush(NULL);
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        execlp("diff", "diff", "-u", "--", before, after, (char *)NULL);
        perror("diff");
        _exit(127);
    }
    int status = wait_child(child);
    return status == 0 || status == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
    enum { NONE, READ, WRITE, READ_WRITE } mode = NONE;
    int times = 0, sizes = 0, differences = 0;
    long timeout = 30;
    const char *socket_option = RW_DEFAULT_SOCKET;
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (argc < 3) {
        usage(stderr);
        return 2;
    }
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-w") == 0 ||
            strcmp(argv[i], "-rw") == 0) {
            if (mode != NONE) {
                usage(stderr);
                return 2;
            }
            mode = strcmp(argv[i], "-r") == 0 ? READ :
                   strcmp(argv[i], "-w") == 0 ? WRITE : READ_WRITE;
        } else if (strcmp(argv[i], "-t") == 0) {
            times = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            sizes = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            differences = 1;
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_option = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            if (rw_number(argv[++i], 1, 86400, &timeout) < 0) {
                usage(stderr);
                return 2;
            }
        } else {
            usage(stderr);
            return 2;
        }
    }
    if (mode == NONE) {
        usage(stderr);
        return 2;
    }
    char path[RW_PATH_MAX], socket_path[RW_PATH_MAX];
    struct stat before, after;
    if (realpath(argv[1], path) == NULL || stat(path, &before) < 0) {
        perror("target");
        return 1;
    }
    if (!S_ISREG(before.st_mode)) {
        fprintf(stderr, "Target must be an existing regular file\n");
        return 1;
    }
    if (mode == READ || mode == READ_WRITE) {
        if (times) {
            show_time("Last modification time", before.st_mtime);
            show_time("Current time", time(NULL));
        }
        if (show_file(path) < 0) {
            perror("read file");
            return 1;
        }
        if (mode == READ)
            return 0;
        char answer[16];
        printf("\nWould you like to modify '%s'? (yes/no): ", path);
        fflush(stdout);
        if (fgets(answer, sizeof(answer), stdin) == NULL) {
            if (ferror(stdin)) {
                perror("confirmation");
                return 1;
            }
            return 0;
        }
        if (strcmp(answer, "no\n") == 0 || strcmp(answer, "no") == 0)
            return 0;
        if (strcmp(answer, "yes\n") != 0 && strcmp(answer, "yes") != 0) {
            fprintf(stderr, "Please answer yes or no\n");
            return 2;
        }
    }
    if (rw_absolute(socket_option, socket_path, sizeof(socket_path)) < 0) {
        perror("socket path");
        return 1;
    }
    int token = acquire(socket_path, path, timeout);
    if (token < 0) {
        perror("edit permission");
        return 1;
    }
    int result = 1, temp_fd = -1, input = -1, temp_created = 0;
    char temporary[RW_PATH_MAX];
    const char *temp_dir = getenv("TMPDIR");
    if (temp_dir == NULL || *temp_dir == '\0')
        temp_dir = "/tmp";
    int length = snprintf(temporary, sizeof(temporary), "%s/readerwriter-XXXXXX", temp_dir);
    if (length < 0 || (size_t)length >= sizeof(temporary)) {
        fprintf(stderr, "Temporary path too long\n");
        goto cleanup;
    }
    temp_fd = mkostemp(temporary, O_CLOEXEC);
    if (temp_fd < 0) {
        perror("temporary file");
        goto cleanup;
    }
    temp_created = 1;
    input = open(path, O_RDONLY | O_CLOEXEC);
    if (input < 0 || fstat(input, &before) < 0 || !S_ISREG(before.st_mode) ||
        rw_copy(input, temp_fd) < 0) {
        perror("snapshot");
        goto cleanup;
    }
    close(input);
    input = -1;
    if (close(temp_fd) < 0) {
        temp_fd = -1;
        perror("snapshot close");
        goto cleanup;
    }
    temp_fd = -1;
    if (times) {
        show_time("Before modification", before.st_mtime);
        show_time("Current time", time(NULL));
    }
    int editor_status = edit(path, token);
    if (editor_status != 0) {
        fprintf(stderr, "Editor failed (status=%d)\n", editor_status);
        goto cleanup;
    }
    if (stat(path, &after) < 0 || !S_ISREG(after.st_mode)) {
        fprintf(stderr, "Edited file is missing or is not a regular file\n");
        goto cleanup;
    }
    int changed = compare(temporary, path);
    if (changed < 0) {
        perror("compare contents");
        goto cleanup;
    }
    if (times) {
        show_time("After modification", after.st_mtime);
        puts(changed ? "There was modification." : "There was no modification.");
    }
    if (sizes && changed)
        printf("Before modification: %lld bytes\nAfter modification: %lld bytes\n",
               (long long)before.st_size, (long long)after.st_size);
    if (differences && changed && show_diff(temporary, path) < 0) {
        fprintf(stderr, "diff failed\n");
        goto cleanup;
    }
    result = 0;

cleanup:
    if (input >= 0)
        close(input);
    if (temp_fd >= 0)
        close(temp_fd);
    if (temp_created && unlink(temporary) < 0) {
        perror("temporary file cleanup");
        result = 1;
    }
    /* Keep permission through stat/diff so the next editor cannot race them. */
    if (rw_send_status(token, RW_DONE) < 0) {
        fprintf(stderr, "Daemon disconnected before edit completion\n");
        result = 1;
    }
    close(token);
    return result;
}
