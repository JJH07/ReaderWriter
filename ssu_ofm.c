#define _GNU_SOURCE
#include "rw_common.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum state { EMPTY, REQUEST, QUEUED, ACTIVE };
struct client {
    int fd;
    enum state state;
    pid_t pid;
    uid_t uid;
    unsigned long long order;
    time_t arrived;
};

static volatile sig_atomic_t stopping;
static FILE *log_file;
static int timestamps, identities, snapshots;
static char log_path[RW_PATH_MAX];

static void stop_server(int signo)
{
    (void)signo;
    stopping = 1;
}

static void log_event(const char *format, ...)
{
    if (timestamps) {
        time_t now = time(NULL);
        struct tm value;
        char stamp[32];
        if (localtime_r(&now, &value) != NULL &&
            strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &value) != 0)
            fprintf(log_file, "[%s] ", stamp);
    }
    va_list arguments;
    va_start(arguments, format);
    vfprintf(log_file, format, arguments);
    va_end(arguments);
    fputc('\n', log_file);
}

static void snapshot_log(void)
{
    char name[RW_PATH_MAX];
    int count = snprintf(name, sizeof(name), "%s.XXXXXX", log_path);
    if (count < 0 || (size_t)count >= sizeof(name)) {
        log_event("Log snapshot failed: path too long");
        return;
    }
    fflush(log_file);
    int output = mkstemp(name);
    if (output < 0) {
        log_event("Log snapshot failed: %s", strerror(errno));
        return;
    }
    int input = open(log_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int success = input >= 0 && rw_copy(input, output) == 0;
    if (input >= 0)
        close(input);
    if (close(output) < 0)
        success = 0;
    if (!success) {
        unlink(name);
        log_event("Log snapshot failed");
    } else {
        log_event("Log snapshot: %s", name);
    }
}

static time_t monotonic_seconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) < 0)
        return 0;
    return value.tv_sec;
}

static void discard(struct client *client)
{
    if (client->state == ACTIVE) {
        log_event("Released pid=%ld", (long)client->pid);
        if (snapshots)
            snapshot_log();
    }
    close(client->fd);
    client->fd = -1;
    client->state = EMPTY;
}

static int active_index(struct client *clients, int count)
{
    for (int i = 0; i < count; ++i)
        if (clients[i].state == ACTIVE)
            return i;
    return -1;
}

static int queued_count(struct client *clients, int count)
{
    int waiting = 0;
    for (int i = 0; i < count; ++i)
        waiting += clients[i].state == QUEUED;
    return waiting;
}

static void grant_next(struct client *clients, int count)
{
    if (stopping || active_index(clients, count) >= 0)
        return;
    for (;;) {
        int next = -1;
        for (int i = 0; i < count; ++i)
            if (clients[i].state == QUEUED &&
                (next < 0 || clients[i].order < clients[next].order))
                next = i;
        if (next < 0)
            return;
        if (rw_send_status(clients[next].fd, RW_GRANTED) < 0) {
            discard(&clients[next]);
            continue;
        }
        clients[next].state = ACTIVE;
        log_event("Granted pid=%ld", (long)clients[next].pid);
        return;
    }
}

static int private_directory(const char *path)
{
    if (mkdir(path, 0700) < 0 && errno != EEXIST)
        return -1;
    struct stat info;
    if (lstat(path, &info) < 0)
        return -1;
    if (!S_ISDIR(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & 0022) != 0 || (info.st_mode & 0300) != 0300) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

/* The lock stays on disk; unlinking it would permit two independent locks. */
static int make_listener(const char *path, int *lock_fd)
{
    char parent[RW_PATH_MAX], lock_path[RW_PATH_MAX];
    struct sockaddr_un address;
    struct stat info;
    if (rw_address(path, &address) < 0)
        return -1;
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (slash == parent)
        slash[1] = '\0';
    else
        *slash = '\0';
    if (private_directory(parent) < 0)
        return -1;
    int length = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    if (length < 0 || (size_t)length >= sizeof(lock_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    *lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (*lock_fd < 0)
        return -1;
    if (fstat(*lock_fd, &info) < 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() || info.st_nlink != 1) {
        errno = EACCES;
        return -1;
    }
    if (flock(*lock_fd, LOCK_EX | LOCK_NB) < 0)
        return -1;
    if (lstat(path, &info) == 0) {
        if (!S_ISSOCK(info.st_mode) || info.st_uid != geteuid()) {
            errno = EEXIST;
            return -1;
        }
        if (unlink(path) < 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 128) < 0) {
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

static int background(void)
{
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) < 0)
        return -1;
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) {
        close(ready[0]);
        close(ready[1]);
        return -1;
    }
    if (child > 0) {
        close(ready[1]);
        char result = 0;
        ssize_t length;
        do {
            length = read(ready[0], &result, 1);
        } while (length < 0 && errno == EINTR);
        close(ready[0]);
        if (length != 1 || result != '1')
            return -1;
        printf("ssu_ofm started: pid=%ld\n", (long)child);
        return 1;
    }
    close(ready[0]);
    if (setsid() < 0)
        _exit(1);
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0)
        _exit(1);
    for (int fd = 0; fd <= 2; ++fd)
        if (dup2(null_fd, fd) < 0)
            _exit(1);
    if (null_fd > 2)
        close(null_fd);
    if (write(ready[1], "1", 1) != 1)
        _exit(1);
    close(ready[1]);
    return 0;
}

static void usage(FILE *stream)
{
    fprintf(stream, "Usage: ssu_ofm FILE [-f] [-l] [-t] [-id] [-n 1..1024]\n"
                    "               [-p LOG_DIRECTORY] [--socket PATH]\n");
}

int main(int argc, char **argv)
{
    char target[RW_PATH_MAX], socket_path[RW_PATH_MAX];
    const char *socket_option = RW_DEFAULT_SOCKET, *log_directory = ".";
    int foreground = 0, capacity = 16, lock_fd = -1;
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-f") == 0)
            foreground = 1;
        else if (strcmp(argv[i], "-l") == 0)
            snapshots = 1;
        else if (strcmp(argv[i], "-t") == 0)
            timestamps = 1;
        else if (strcmp(argv[i], "-id") == 0)
            identities = 1;
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            long value;
            if (rw_number(argv[++i], 1, 1024, &value) < 0) {
                usage(stderr);
                return 2;
            }
            capacity = (int)value;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            log_directory = argv[++i];
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_option = argv[++i];
        } else {
            usage(stderr);
            return 2;
        }
    }
    struct stat info;
    if (realpath(argv[1], target) == NULL || stat(target, &info) < 0) {
        perror("target");
        return 1;
    }
    if (!S_ISREG(info.st_mode)) {
        fprintf(stderr, "Target must be an existing regular file\n");
        return 1;
    }
    if (rw_absolute(socket_option, socket_path, sizeof(socket_path)) < 0) {
        perror("socket path");
        return 1;
    }
    umask(0077);
    int listener = make_listener(socket_path, &lock_fd);
    if (listener < 0) {
        perror("listener (check directory permissions / existing daemon)");
        if (lock_fd >= 0)
            close(lock_fd);
        return 1;
    }
    int result = 1;
    struct client *clients = NULL;
    struct pollfd *polls = NULL;
    if (private_directory(log_directory) < 0) {
        perror("log directory");
        goto cleanup;
    }
    int length = snprintf(log_path, sizeof(log_path), "%s/ssu_log.txt", log_directory);
    if (length < 0 || (size_t)length >= sizeof(log_path)) {
        fprintf(stderr, "Log path too long\n");
        goto cleanup;
    }
    int log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (log_fd < 0 || (log_file = fdopen(log_fd, "a")) == NULL) {
        perror("log file");
        if (log_fd >= 0)
            close(log_fd);
        goto cleanup;
    }
    setvbuf(log_file, NULL, _IOLBF, 0);
    int count = capacity + 17; /* bounded room for requests not yet received */
    clients = calloc((size_t)count, sizeof(*clients));
    polls = calloc((size_t)count + 1, sizeof(*polls));
    if (clients == NULL || polls == NULL) {
        perror("allocate clients");
        goto cleanup;
    }
    struct sigaction action = {0};
    action.sa_handler = stop_server;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) < 0 || sigaction(SIGINT, &action, NULL) < 0) {
        perror("sigaction");
        goto cleanup;
    }
    if (!foreground) {
        int status = background();
        if (status < 0) {
            perror("daemon startup");
            goto cleanup;
        }
        if (status > 0) {
            /* Child owns cleanup of the socket pathname and inherited lock. */
            fclose(log_file);
            close(listener);
            close(lock_fd);
            free(clients);
            free(polls);
            return 0;
        }
    }
    log_event("Started pid=%ld target=%s capacity=%d", (long)getpid(), target, capacity);
    unsigned long long sequence = 0;
    for (;;) {
        if (stopping) {
            for (int i = 0; i < count; ++i)
                if (clients[i].state != EMPTY && clients[i].state != ACTIVE) {
                    rw_send_status(clients[i].fd, RW_SHUTDOWN);
                    discard(&clients[i]);
                }
            if (active_index(clients, count) < 0)
                break;
        }
        polls[0].fd = stopping ? -1 : listener;
        polls[0].events = POLLIN;
        for (int i = 0; i < count; ++i) {
            polls[i + 1].fd = clients[i].state == EMPTY ? -1 : clients[i].fd;
            polls[i + 1].events = POLLIN;
        }
        int ready = poll(polls, (nfds_t)count + 1, 250);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            log_event("poll failed: %s", strerror(errno));
            goto cleanup;
        }
        /* Process existing connections before admitting new clients. */
        for (int i = 0; i < count; ++i) {
            struct client *client = &clients[i];
            if (client->state == EMPTY)
                continue;
            short events = polls[i + 1].revents;
            if (events & (POLLHUP | POLLERR | POLLNVAL)) {
                discard(client);
                continue;
            }
            if (!(events & POLLIN)) {
                if (client->state == REQUEST && monotonic_seconds() - client->arrived >= 5)
                    discard(client);
                continue;
            }
            struct rw_request request;
            ssize_t received = recv(client->fd, &request, sizeof(request), MSG_TRUNC);
            if (received < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            if (client->state == ACTIVE) {
                uint32_t status = 0;
                if (received == (ssize_t)sizeof(status))
                    memcpy(&status, &request, sizeof(status));
                if (received <= 0 || status == RW_DONE)
                    discard(client);
                /* Unexpected packets cannot release someone else's token. */
                continue;
            }
            if (client->state != REQUEST || received != (ssize_t)sizeof(request) ||
                request.magic != RW_MAGIC ||
                memchr(request.path, '\0', sizeof(request.path)) == NULL ||
                strcmp(request.path, target) != 0) {
                rw_send_status(client->fd, RW_INVALID);
                discard(client);
                continue;
            }
            if (queued_count(clients, count) >= capacity && active_index(clients, count) >= 0) {
                rw_send_status(client->fd, RW_BUSY);
                discard(client);
                continue;
            }
            client->order = sequence++;
            client->state = QUEUED;
            if (identities)
                log_event("Requested pid=%ld uid=%ld", (long)client->pid, (long)client->uid);
            else
                log_event("Requested pid=%ld", (long)client->pid);
            if (rw_send_status(client->fd, RW_QUEUED) < 0)
                discard(client);
            grant_next(clients, count);
        }
        grant_next(clients, count);
        if (!stopping && (polls[0].revents & POLLIN)) {
            /* Limit each batch so a connection flood cannot starve releases. */
            for (int accepted = 0; accepted < 32; ++accepted) {
                int fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0)
                    break;
                struct ucred peer;
                socklen_t size = sizeof(peer);
                int slot = -1;
                for (int i = 0; i < count; ++i)
                    if (clients[i].state == EMPTY) {
                        slot = i;
                        break;
                    }
                if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) < 0 ||
                    peer.uid != geteuid() || slot < 0) {
                    rw_send_status(fd, RW_BUSY);
                    close(fd);
                    continue;
                }
                clients[slot] = (struct client){.fd = fd, .state = REQUEST,
                    .pid = peer.pid, .uid = peer.uid, .arrived = monotonic_seconds()};
            }
        }
    }
    log_event("Stopped");
    result = 0;

cleanup:
    if (clients != NULL)
        for (int i = 0; i < capacity + 17; ++i)
            if (clients[i].state != EMPTY)
                close(clients[i].fd);
    free(clients);
    free(polls);
    if (log_file != NULL)
        fclose(log_file);
    close(listener);
    unlink(socket_path);
    close(lock_fd);
    return result;
}
