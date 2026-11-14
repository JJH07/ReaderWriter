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
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#define BIT_r 1
#define BIT_w 2
#define BIT_rw 4
#define BIT_t 8
#define BIT_s 16
#define BIT_d 32
#define FIFO_FILE "./tmp/fifo"

static int bitset, temp_created, permission, edit_lock = -1;
static pid_t ofm;
static char *filename, tempfile[] = "tempXXXXXX";
static sigset_t signals, original_mask;

static int parse(int argc, char **argv)
{
    if (argc < 3 || (strcmp(argv[2], "-r") != 0 && strcmp(argv[2], "-w") != 0 &&
                     strcmp(argv[2], "-rw") != 0)) {
        errno = EINVAL;
        perror("Read / Write option error. Available = < -r | -w | -rw >\n");
        return -1;
    }
    filename = argv[1];
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-r") == 0)
            bitset |= BIT_r;
        else if (strcmp(argv[i], "-w") == 0)
            bitset |= BIT_w;
        else if (strcmp(argv[i], "-rw") == 0)
            bitset |= BIT_rw;
        else if (strcmp(argv[i], "-t") == 0)
            bitset |= BIT_t;
        else if (strcmp(argv[i], "-s") == 0)
            bitset |= BIT_s;
        else if (strcmp(argv[i], "-d") == 0)
            bitset |= BIT_d;
        else {
            errno = EINVAL;
            perror("Option error. AVAILABLE = < [-r | -w | -rw] | -t | -s | -d >\n");
            return -1;
        }
    }
    if (!!(bitset & BIT_r) + !!(bitset & BIT_w) + !!(bitset & BIT_rw) > 1) {
        errno = EINVAL;
        perror("THERE IS MORE THAN 1 READ/WRITE OPTION.\n VALID = ONLY ONE OF < -r | -w | -rw >");
        return -1;
    }
    /* Keep the original process discovery, without trusting a failed read. */
    FILE *stream = popen("ps -C ssu_ofm", "r");
    if (stream != NULL) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), stream) != NULL) {
            int pid;
            while (fscanf(stream, "%d", &pid) == 1) {
                if (pid > 0) {
                    /* Ignore a defunct daemon left by a previous session. */
                    char path[64], line[4096];
                    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
                    FILE *state = fopen(path, "r");
                    int zombie = 0;
                    if (state != NULL) {
                        if (fgets(line, sizeof(line), state) != NULL) {
                            char *end = strrchr(line, ')');
                            zombie = end && end[1] == ' ' && end[2] == 'Z';
                        }
                        fclose(state);
                    }
                    if (!zombie) {
                        ofm = pid;
                        break;
                    }
                }
                if (fgets(buffer, sizeof(buffer), stream) == NULL)
                    break;
            }
        }
        pclose(stream);
    }
    return 0;
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

static int run_cat(void)
{
    /* Keep the original stdio buffering: redirected child output can precede
     * the parent's buffered report. exec/_exit do not flush the child's copy. */
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        sigprocmask(SIG_SETMASK, &original_mask, NULL);
        execl("/bin/cat", "cat", filename, (char *)NULL);
        perror("execl(cat)");
        _exit(127);
    }
    return wait_child(child);
}

static void waiting(void)
{
    printf("Waiting for Token...%s", filename);
    if (bitset & BIT_t) {
        time_t seconds = time(NULL);
        struct tm value;
        if (localtime_r(&seconds, &value) != NULL)
            printf("[%d-%02d-%02d %02d:%02d:%02d]", value.tm_year + 1900,
                   value.tm_mon + 1, value.tm_mday, value.tm_hour, value.tm_min, value.tm_sec);
    }
    if ((bitset & BIT_w) || (bitset & BIT_t))
        printf("\n");
}

static int receive_signal(long seconds, long nanoseconds)
{
    siginfo_t info;
    struct timespec interval = {.tv_sec = seconds, .tv_nsec = nanoseconds};
    int signo = sigtimedwait(&signals, &info, &interval);
    if (signo < 0)
        return errno == EINTR || errno == EAGAIN ? 0 : -1;
    if (info.si_pid != ofm)
        return 0;
    if (signo == SIGUSR2) {
        printf("Can't Manage File(%s) : Incorrect ofm filename\n", filename);
        return -1;
    }
    if (signo == SIGUSR1)
        permission = 1;
    return 0;
}

static int request_edit(void)
{
    int fd = open(FIFO_FILE, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        printf("error in fifoopen\n");
        return -1;
    }
    struct stat info;
    if (fstat(fd, &info) < 0 || !S_ISFIFO(info.st_mode)) {
        close(fd);
        printf("error in fifoopen\n");
        return -1;
    }
    time_t last_print = 0;
    for (;;) {
        if (kill(ofm, 0) < 0) {
            close(fd);
            return -1;
        }
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            int unread;
            if (ioctl(fd, FIONREAD, &unread) < 0) {
                close(fd);
                return -1;
            }
            if (unread == 0)
                break;
            flock(fd, LOCK_UN);
        } else if (errno != EWOULDBLOCK && errno != EINTR) {
            close(fd);
            return -1;
        }
        time_t now = time(NULL);
        if (now != last_print) {
            waiting();
            last_print = now;
        }
        if (receive_signal(0, 10000000) < 0) {
            close(fd);
            return -1;
        }
    }
    size_t length = strlen(filename) + ((bitset & BIT_rw) ? 1u : 0u);
    long atomic_limit = fpathconf(fd, _PC_PIPE_BUF);
    ssize_t written = -1;
    if (atomic_limit > 0 && length <= (size_t)atomic_limit && length <= 4096) {
        do {
            written = write(fd, filename, length);
        } while (written < 0 && errno == EINTR);
    }
    if (written != (ssize_t)length || kill(ofm, SIGUSR1) < 0) {
        printf("write error in fifo write\n");
        close(fd);
        return -1;
    }
    /* Do not let the next writer notify the daemon before it consumes this name. */
    for (;;) {
        int unread;
        if (ioctl(fd, FIONREAD, &unread) < 0) {
            close(fd);
            return -1;
        }
        if (unread == 0) {
            close(fd);
            fd = -1;
            break;
        }
        if (kill(ofm, 0) < 0 || receive_signal(0, 10000000) < 0) {
            close(fd);
            return -1;
        }
        time_t now = time(NULL);
        if (!permission && now != last_print) {
            waiting();
            last_print = now;
        }
    }
    while (!permission) {
        if (receive_signal(0, 0) < 0)
            return -1;
        if (permission)
            break;
        waiting();
        if (kill(ofm, 0) < 0 || receive_signal(1, 0) < 0)
            return -1;
    }
    return 0;
}

static int edit_file(void)
{
    edit_lock = open("tmp", O_RDONLY | O_DIRECTORY);
    if (edit_lock < 0 || flock(edit_lock, LOCK_EX) < 0)
        return -1;
    int output = mkstemp(tempfile);
    if (output < 0)
        return -1;
    temp_created = 1;
    fcntl(output, F_SETFD, FD_CLOEXEC);
    int input = open(filename, O_RDONLY | O_CLOEXEC);
    if (input < 0) {
        close(output);
        return -1;
    }
    char buffer[8192];
    int success = 1;
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            success = 0;
            break;
        }
        if (count == 0)
            break;
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t size = write(output, buffer + offset, (size_t)(count - offset));
            if (size < 0 && errno == EINTR)
                continue;
            if (size <= 0) {
                success = 0;
                break;
            }
            offset += size;
        }
        if (!success)
            break;
    }
    close(input);
    if (close(output) < 0)
        success = 0;
    if (!success)
        return -1;
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        /* The inherited directory lock survives wrapper-only termination. */
        sigprocmask(SIG_SETMASK, &original_mask, NULL);
        execl("/usr/bin/vim", "vim", filename, (char *)NULL);
        perror("execl(vim)");
        _exit(127);
    }
    return wait_child(child);
}

int main(int argc, char **argv)
{
    if (parse(argc, argv) < 0)
        return 1;
    sigemptyset(&signals);
    sigaddset(&signals, SIGUSR1);
    sigaddset(&signals, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &signals, &original_mask) < 0)
        return 1;
    struct stat statbuf, statbuf2;
    if (lstat(filename, &statbuf) < 0) {
        perror("lstat() error\n");
        return 1;
    }
    if (!(bitset & BIT_r) && ofm == 0) {
        printf("where is ssu_ofm?\nssu_vim error\n");
        return 1;
    }
    if (bitset & BIT_t) {
        struct tm mtime, now;
        time_t rawTime = time(NULL);
        if (localtime_r(&statbuf.st_mtime, &mtime) == NULL ||
            localtime_r(&rawTime, &now) == NULL)
            return 1;
        printf("##[Modification Time]##\n");
        printf("Last Modification time of '%s': [%d-%02d-%02d %02d:%02d:%02d]\n",
               filename, mtime.tm_year + 1900, mtime.tm_mon + 1, mtime.tm_mday,
               mtime.tm_hour, mtime.tm_min, mtime.tm_sec);
        printf("Current time: [%d-%02d-%02d %02d:%02d:%02d]\n",
               now.tm_year + 1900, now.tm_mon + 1, now.tm_mday,
               now.tm_hour, now.tm_min, now.tm_sec);
    }
    if (bitset & BIT_r)
        return run_cat() == 0 ? 0 : 1;
    int should_edit = !!(bitset & BIT_w);
    if (bitset & BIT_rw) {
        if (run_cat() != 0)
            return 1;
        printf("\nWould you like to modify '%s'? (yes/no) : ", filename);
        char buffer[256];
        should_edit = scanf("%255s", buffer) == 1 && strcmp(buffer, "yes") == 0;
    }
    int result = 1;
    if (should_edit && (request_edit() < 0 || edit_file() != 0))
        goto cleanup;
    if (lstat(filename, &statbuf2) < 0) {
        printf("lstat error\n");
        goto cleanup;
    }
    int changed = difftime(statbuf.st_mtime, statbuf2.st_mtime) != 0.0;
    if (bitset & BIT_t) {
        printf("##[Modification Time]##\n");
        printf("%s", changed ? "There was modification.\n" : "There was no modification.\n");
    }
    if ((bitset & BIT_s) && changed) {
        printf("##[File Size]##\n");
        printf("Before modification : %ld(bytes)\n", (long)statbuf.st_size);
        printf("After modification : %ld(bytes)\n", (long)statbuf2.st_size);
    }
    if ((bitset & BIT_d) && changed && temp_created) {
        printf("##[Compare with Previous File]##\n");
        pid_t child = fork();
        if (child < 0) {
            printf("fork() error");
            goto cleanup;
        }
        if (child == 0) {
            sigprocmask(SIG_SETMASK, &original_mask, NULL);
            execl("/usr/bin/diff", "diff", tempfile, filename, (char *)NULL);
            perror("execl(diff)");
            _exit(127);
        }
        int status = wait_child(child);
        if (status != 0 && status != 1)
            goto cleanup;
    }
    result = 0;
cleanup:
    if (temp_created && unlink(tempfile) < 0)
        result = 1;
    if (edit_lock >= 0)
        close(edit_lock);
    if (permission && kill(ofm, SIGUSR2) < 0)
        result = 1;
    return result;
}
