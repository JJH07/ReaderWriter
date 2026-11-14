#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#define BIT_l 1
#define BIT_t 2
#define BIT_n 4
#define BIT_p 8
#define BIT_id 16
#define FIFO "./tmp/fifo"

static char *filename, *directory, logPath[512] = "./ssu_log.txt";
static int bitset, queuesize = 16;
static pid_t *queue, owner;
static int front, tail, q_cnt, fifofd = -1, edit_lock = -1;

static void timestamp(void)
{
    time_t seconds = time(NULL);
    struct tm value;
    if (localtime_r(&seconds, &value) != NULL)
        printf("[%d-%02d-%02d %02d:%02d:%02d] ", value.tm_year + 1900,
               value.tm_mon + 1, value.tm_mday, value.tm_hour, value.tm_min, value.tm_sec);
}

static int parse(int argc, char **argv)
{
    if (argc < 2)
        goto invalid;
    filename = argv[1];
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-l") == 0)
            bitset |= BIT_l;
        else if (strcmp(argv[i], "-t") == 0)
            bitset |= BIT_t;
        else if (strcmp(argv[i], "-id") == 0)
            bitset |= BIT_id;
        else if (strcmp(argv[i], "-n") == 0) {
            if (++i >= argc)
                goto invalid;
            char *end;
            errno = 0;
            long count = strtol(argv[i], &end, 10);
            if (errno || end == argv[i] || *end || count < 0 || count > INT_MAX)
                goto invalid;
            queuesize = (int)count;
            bitset |= BIT_n;
        } else if (strcmp(argv[i], "-p") == 0) {
            if (++i >= argc)
                goto invalid;
            directory = argv[i];
            bitset |= BIT_p;
            if (mkdir(directory, 0777) < 0 && errno != EEXIST) {
                perror("mkdir");
                return -1;
            }
            int count = snprintf(logPath, sizeof(logPath), "./%s/ssu_log.txt", directory);
            if (count < 0 || (size_t)count >= sizeof(logPath))
                goto invalid;
        } else {
            goto invalid;
        }
    }
    return 0;
invalid:
    errno = EINVAL;
    perror("Invalid Daemon Option\n");
    return -1;
}

static int alive(pid_t pid)
{
    if (pid <= 0 || (kill(pid, 0) < 0 && errno == ESRCH))
        return 0;
    /* kill(pid, 0) also succeeds for zombies; they cannot complete a request. */
    char path[64], buffer[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *stream = fopen(path, "r");
    if (stream != NULL) {
        if (fgets(buffer, sizeof(buffer), stream) != NULL) {
            char *end = strrchr(buffer, ')');
            if (end != NULL && end[1] == ' ' && end[2] == 'Z') {
                fclose(stream);
                return 0;
            }
        }
        fclose(stream);
    }
    return 1;
}

static void prune_queue(void)
{
    int remaining = q_cnt;
    for (int i = 0; i < remaining; ++i) {
        pid_t pid = queue[front];
        front = (front + 1) % queuesize;
        --q_cnt;
        if (alive(pid)) {
            queue[tail] = pid;
            tail = (tail + 1) % queuesize;
            ++q_cnt;
        }
    }
}

static void next_owner(void)
{
    while (owner == 0 && q_cnt > 0) {
        pid_t pid = queue[front];
        front = (front + 1) % queuesize;
        --q_cnt;
        if (alive(pid) && kill(pid, SIGUSR1) == 0)
            owner = pid;
    }
}

static void copy_log(void)
{
    char newLog[512];
    struct tm value;
    time_t seconds = time(NULL);
    if (localtime_r(&seconds, &value) == NULL)
        return;
    int count;
    if (bitset & BIT_p)
        count = snprintf(newLog, sizeof(newLog), "./%s/[%d-%02d-%02d %02d:%02d:%02d]",
                         directory, value.tm_year + 1900, value.tm_mon + 1,
                         value.tm_mday, value.tm_hour, value.tm_min, value.tm_sec);
    else
        count = snprintf(newLog, sizeof(newLog), "[%d-%02d-%02d %02d:%02d:%02d]",
                         value.tm_year + 1900, value.tm_mon + 1,
                         value.tm_mday, value.tm_hour, value.tm_min, value.tm_sec);
    if (count < 0 || (size_t)count >= sizeof(newLog))
        return;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        execl("/bin/cp", "cp", logPath, newLog, (char *)NULL);
        _exit(127);
    }
    if (child > 0)
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
}

static void completed(pid_t pid)
{
    if (bitset & BIT_t)
        timestamp();
    printf("Finished Process ID : %d\n", pid);
    fflush(stdout);
    if (bitset & BIT_l)
        copy_log();
    owner = 0;
    next_owner();
}

static int setup_fifo(void)
{
    struct stat info;
    if (mkdir("tmp", 0777) < 0 && errno != EEXIST)
        return -1;
    if (lstat("tmp", &info) < 0 || !S_ISDIR(info.st_mode))
        return -1;
    if (mkfifo(FIFO, 0666) < 0 && errno != EEXIST)
        return -1;
    if (lstat(FIFO, &info) < 0 || !S_ISFIFO(info.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    fifofd = open(FIFO, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fifofd < 0)
        return -1;
    /* fcntl lock is distinct from the clients' flock request mutex on Linux. */
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (fcntl(fifofd, F_SETLK, &lock) < 0)
        return -1;
    edit_lock = open("tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return edit_lock < 0 ? -1 : 0;
}

static ssize_t peek_request(char *buffer, size_t size)
{
    /* Inspect a full-queue request without consuming its FIFO bytes. The
     * sender keeps its existing writer lock until we actually consume them. */
    int preview[2];
    if (pipe2(preview, O_NONBLOCK | O_CLOEXEC) < 0)
        return -1;
    ssize_t count = tee(fifofd, preview[1], size, SPLICE_F_NONBLOCK);
    if (count > 0)
        count = read(preview[0], buffer, (size_t)count);
    int saved_errno = errno;
    close(preview[0]);
    close(preview[1]);
    errno = saved_errno;
    return count;
}

static void serve(const sigset_t *signals)
{
    siginfo_t pending = {0};
    int have_pending = 0;
    for (;;) {
        prune_queue();
        if (owner != 0 && !alive(owner) && flock(edit_lock, LOCK_EX | LOCK_NB) == 0) {
            flock(edit_lock, LOCK_UN);
            completed(owner);
        }
        next_owner();
        if (!have_pending && flock(fifofd, LOCK_EX | LOCK_NB) == 0) {
            /* No live writer can be awaiting consumption while we hold this
             * lock. A dead writer may have sent SIGUSR1 before releasing it;
             * discard that notice together with its bytes, before a successor
             * can write. Otherwise the old sender can consume the new name. */
            sigset_t requests;
            sigemptyset(&requests);
            sigaddset(&requests, SIGUSR1);
            struct timespec immediate = {0};
            int notice;
            do {
                notice = sigtimedwait(&requests, NULL, &immediate);
            } while (notice == SIGUSR1 || (notice < 0 && errno == EINTR));
            char stale[4096];
            while (read(fifofd, stale, sizeof(stale)) > 0) {}
            flock(fifofd, LOCK_UN);
        }
        int consume_request = have_pending &&
            (!alive(pending.si_pid) || owner == 0 || q_cnt < queuesize);
        if (have_pending && !consume_request) {
            /* An invalid filename needs no queue slot: reject it even while
             * the queue is full, retaining backpressure for valid requests. */
            char preview[4097];
            ssize_t count = peek_request(preview, sizeof(preview) - 1);
            if (count > 0) {
                preview[count] = '\0';
                consume_request = strcmp(preview, filename) != 0;
            }
        }
        if (consume_request) {
            /* Writers serialize write+signal until these bytes are consumed. */
            char buffer[4097];
            ssize_t count = read(fifofd, buffer, sizeof(buffer) - 1);
            if (count < 0 && errno == EINTR)
                continue;
            if (count > 0) {
                buffer[count] = '\0';
                if (alive(pending.si_pid)) {
                    if (strcmp(buffer, filename) != 0) {
                        kill(pending.si_pid, SIGUSR2);
                    } else {
                        if (bitset & BIT_t)
                            timestamp();
                        printf("Requested Process ID : %d, Requested Filename : %s\n",
                               pending.si_pid, buffer);
                        if (bitset & BIT_id) {
                            struct passwd *data = getpwuid(pending.si_uid);
                            if (data != NULL)
                                printf("User : %s, UID : %d, GID : %d\n", data->pw_name,
                                       data->pw_uid, data->pw_gid);
                        }
                        fflush(stdout);
                        if (owner == 0) {
                            if (kill(pending.si_pid, SIGUSR1) == 0)
                                owner = pending.si_pid;
                        } else {
                            queue[tail] = pending.si_pid;
                            tail = (tail + 1) % queuesize;
                            ++q_cnt;
                        }
                    }
                }
            }
            have_pending = 0;
        }
        struct timespec interval = {.tv_sec = 1};
        siginfo_t info;
        int signo = sigtimedwait(signals, &info, &interval);
        if (signo == SIGUSR1 && !have_pending) {
            pending = info;
            have_pending = 1;
        } else if (signo == SIGUSR2 && info.si_pid == owner && owner != 0) {
            completed(owner);
        } else if (signo < 0 && errno != EINTR && errno != EAGAIN) {
            perror("sigtimedwait");
            return;
        }
    }
}

static int ssu_daemon_init(void)
{
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGUSR1);
    sigaddset(&signals, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &signals, NULL) < 0)
        return -1;
    queue = calloc((size_t)(queuesize ? queuesize : 1), sizeof(*queue));
    if (queue == NULL)
        return -1;
    int ready[2];
    if (pipe2(ready, O_CLOEXEC) < 0) {
        free(queue);
        return -1;
    }
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) {
        close(ready[0]);
        close(ready[1]);
        free(queue);
        return -1;
    }
    if (child != 0) {
        close(ready[1]);
        char status = 0;
        ssize_t count;
        do {
            count = read(ready[0], &status, 1);
        } while (count < 0 && errno == EINTR);
        close(ready[0]);
        free(queue);
        return count == 1 && status == '1' ? 0 : -1;
    }
    close(ready[0]);
    if (setsid() < 0)
        _exit(1);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    for (int fd = 0; fd < getdtablesize(); ++fd)
        if (fd != ready[1])
            close(fd);
    umask(0);
    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0)
        _exit(1);
    for (int fd = 0; fd < 3; ++fd)
        if (dup2(nullfd, fd) < 0)
            _exit(1);
    if (nullfd > 2)
        close(nullfd);
    int logfd = open(logPath, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0777);
    if (logfd < 0 || dup2(logfd, STDOUT_FILENO) < 0)
        _exit(1);
    if (logfd != STDOUT_FILENO)
        close(logfd);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (setup_fifo() < 0)
        _exit(1);
    if (bitset & BIT_t)
        timestamp();
    printf("<<Daemon Process Initialized with pid : %d>>\n", getpid());
    printf("Initialized with Default Value : %d\n", queuesize);
    fflush(stdout);
    if (write(ready[1], "1", 1) != 1)
        _exit(1);
    close(ready[1]);
    serve(&signals);
    close(edit_lock);
    close(fifofd);
    free(queue);
    return -1;
}

int main(int argc, char **argv)
{
    if (parse(argc, argv) < 0)
        return 1;
    printf("Daemon Process Initialization\n");
    if (ssu_daemon_init() < 0) {
        fprintf(stderr, "ssu_daemon_init failed\n");
        return 1;
    }
    return 0;
}
