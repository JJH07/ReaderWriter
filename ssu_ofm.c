#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <pwd.h>
#include <time.h>

#define BIT_l 1
#define BIT_t 2
#define BIT_n 4
#define BIT_p 8
#define BIT_id 16
#define FIFO "./tmp/fifo" // fifo파일 경로입니다.

void parse(int argc, char *argv[]);
int ssu_daemon_init(); // 데몬프로세스 실행함수입니다.
static void sig_usr(int signo, siginfo_t *si, ucontext_t *uc); // 시그널 처리함수입니다.

char *filename, *directory, logPath[512] = "./ssu_log.txt";
int bitset, log_fd;
int *queue, queuesize = 16, front, tail, q_cnt; // 큐.
int fifofd; //fifo 파일 디스크립터입니다

int is_Using = 0; //현재 관리대상파일이 사용중인지를 확인하기 위한 변수입니다. 

int main(int argc, char *argv[])
{
	parse(argc, argv);
	
    printf("Daemon Process Initialization\n");
    if (ssu_daemon_init(argc, argv) < 0) {
        fprintf(stderr, "ssu_daemon_init failed\n");
        exit(1);
    }
    return 0;
}
void parse(int argc, char *argv[])
{
	filename = argv[1];
	for(int i = 2; i < argc; i++)
	{
		if(strcmp(argv[i], "-l") == 0)
		{
			bitset |= BIT_l;
		}
		else if(strcmp(argv[i], "-t") == 0)
		{
			bitset |= BIT_t;
		}
		else if(strcmp(argv[i], "-n") == 0)
		{
			bitset |= BIT_n;
			if(i + 1 >= argc)
			{
				perror("Invalid Daemon Option\n");
				exit(1);
			}
			queuesize = atoi(argv[++i]);
		}
		else if(strcmp(argv[i], "-p") == 0)
		{
			bitset |= BIT_p;
			if(i + 1 >= argc)
			{
				perror("Invalid Daemon Option\n");
				exit(1);
			}
			directory = argv[++i];
			mkdir(directory, 0777);
			sprintf(logPath, "./%s/ssu_log.txt", directory);
		}
		else if(strcmp(argv[i], "-id") == 0)
		{
			bitset |= BIT_id;
		}
		else
		{
			perror("Invalid Daemon Option\n");
			exit(1);
		}
	}
}
int ssu_daemon_init() 
{
    pid_t pid;
    int fd; // 데몬프로세스 설정을 위한 변수입니다.
	
	char buf[256]; // IO버퍼입니다.
	
	struct sigaction act; // 시그널 설정을 위한 변수입니다.
	sigset_t sig;
	
	struct tm *strtime;
	time_t timeinfo; //시간값 저장을 위한 변수들입니다.
	
	if ((pid = fork()) < 0)
	{
        fprintf(stderr, "fork error\n");
        exit(1);
    }
    else if (pid != 0) // 부모를 종료시켜 고아프로세스로 만듬
	{	
        exit(0);
	}
    setsid();  //새 프로세스 그룹 생성
	signal(SIGTTIN, SIG_IGN); //터미널 입출력 시그널 무시
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);

    for (int _fd = 0; _fd < getdtablesize(); _fd++) //모든 파일 디스크립터 닫기
	{
       close(_fd);
	}
    umask(0);  //파일 생성 마스크 해제
    chdir("./");  //작업 디렉터리 이동
    fd = open("/dev/null", O_RDWR); //STDIN, STDOUT, STDERR 무효화
    dup(0);
    dup(0);
	
	if((log_fd = open(logPath, O_RDWR | O_CREAT | O_APPEND, 0777)) < 0)  //로그파일 생성합니다.
	{
		perror("open");
		exit(1);
	}
	dup2(log_fd, 1);

	if(bitset & BIT_t)
	{
		time(&timeinfo);
		strtime = localtime(&timeinfo);
		printf("[%d-%02d-%02d %02d:%02d:%02d] ", strtime->tm_year+1900, strtime->tm_mon+1, strtime->tm_mday, strtime->tm_hour, strtime->tm_min, strtime->tm_sec);
	}
	pid = getpid(); //PID 얻어와서
    printf("<<Daemon Process Initialized with pid : %d>>\n", pid);

	queue = (int *)malloc(sizeof(int) * queuesize); // 큐사이즈에 따라 큐 정보가 들어갈 공간을 동적 할당합니다.
	for(int i = 0; i < queuesize; i++) // 초기화합니다.
	{
		queue[i] = 0;
	}
	printf("Initialized with Default Value : %d\n", queuesize);
	close(fd);
	
	act.sa_flags = SA_SIGINFO; //시그널 처리를 위한 설정합니다.
	act.sa_sigaction = (void (*)(int, siginfo_t *, void *))sig_usr;
	sigemptyset(&act.sa_mask);
	sigemptyset(&sig);
	
	if(sigaction(SIGUSR1, &act, (struct sigaction *)NULL) < 0)
	{
		perror("sigaction(SIGUSR1)");
		exit(1);
	}
	if(sigaction(SIGUSR2, &act, (struct sigaction *)NULL) < 0)
	{
		perror("sigaction(SIGUSR2)");
		exit(1);
	}
	mkdir("tmp", 0666);
	if(mkfifo(FIFO, 0666) != -1) //fifo파일 생성합니다. 파일이 있는 경우에는
	{
		unlink(FIFO); // 제거하고
		mkfifo(FIFO, 0666); //다시 생성합니다.
	}
	if((fifofd = open(FIFO, O_RDWR)) < 0) //생성된 fifo파일을 엽니다.
	{
		perror("opening fifo\n");
		exit(1);
	}
	
	while(1)
	{
		sigsuspend(&sig); // 시그널을 계속 받도록 설정합니다.
    }
	free(queue); // 동적할당 해제하고
	close(fifofd); // 파일 닫고

	if(log_fd != -1)
	{
		close(log_fd);
	}
	return 0; //종료합니다.
}

static void sig_usr(int signo, siginfo_t *si, ucontext_t *uc) //시그널 처리함수입니다.
{
	pid_t pid;
	int fd, _len;
	
	char buf[256]; // fifo파일로부터 받아온 정보가 담기는 변수입니다.

	struct passwd *data; // id 옵션을 위한 구조체변수입니다.
	struct tm *strtime; // 시간 정보를 얻기 위한 구조체변수입니다.
	time_t timeinfo; // 시간정보를 위한 변수입니다.

	memset(buf, 0, sizeof(buf)); //초기화합니다.
	if(signo == SIGUSR1) //SIGUSR1 정보가 들어오면
	{
		while((_len = read(fifofd, buf, 256)) < 0)
		{}
		if(strcmp(buf, filename) != 0)
		{
			kill(si->si_pid, SIGUSR2); //파일이 관리대상파일인지를 확인하고 만약 아니라면 SIGUSR2를 전달합니다.
			return ; //그리고 종료합니다.
		}

		if(bitset & BIT_t)
		{
			time(&timeinfo);
			strtime = localtime(&timeinfo);
			printf("[%d-%02d-%02d %02d:%02d:%02d] ", strtime->tm_year+1900, strtime->tm_mon+1, strtime->tm_mday, strtime->tm_hour, strtime->tm_min, strtime->tm_sec);
		}
		printf("Requested Process ID : %d, Requested Filename : %s\n", si->si_pid, buf);

		if(bitset & BIT_id)
		{
			data = getpwuid(si->si_uid);
			printf("User : %s, UID : %d, GID : %d\n", data->pw_name, data->pw_uid, data->pw_gid);
		}

		if(is_Using)
		{
			if(q_cnt < queuesize)
			{
				queue[tail] = si->si_pid;
				++q_cnt;
				tail = (tail + 1) % queuesize;
			}
		}
		else
		{
			is_Using = 1;
			if(q_cnt == 0)
			{
				kill(si->si_pid, SIGUSR1);
			}
			else
			{
				kill(queue[front], SIGUSR1);
				queue[tail] = si->si_pid;
				front = (front + 1) % queuesize;
				tail = (tail + 1) % queuesize;
			}
		}
		close(fd);
	}
	
	else if(signo == SIGUSR2) // SIGUSR2가 들어오면
	{
		if(bitset & BIT_t)
		{
			time(&timeinfo);
			strtime = localtime(&timeinfo);
			printf("[%d-%02d-%02d %02d:%02d:%02d] ", strtime->tm_year+1900, strtime->tm_mon+1, strtime->tm_mday, strtime->tm_hour, strtime->tm_min, strtime->tm_sec);
		}
		printf("Finished Process ID : %d\n", si->si_pid); // SIGUSR2가 들어왔다는 것은 파일 수정이 끝나서 해당 작업 프로세스가 종료되었다는 뜻이므로 로그에 저장합니다.

		if(bitset & BIT_l) // l옵션이 존재하는 경우
		{
			char newLog[512];
			time(&timeinfo);
			strtime = localtime(&timeinfo); // 시그널 받은 시간에 대한 정보를 저장해서
			if(bitset & BIT_p)
			{
				sprintf(newLog, "./%s/[%d-%02d-%02d %02d:%02d:%02d]", directory, strtime->tm_year+1900, strtime->tm_mon+1, strtime->tm_mday, strtime->tm_hour, strtime->tm_min, strtime->tm_sec);
			}
			else
			{
				sprintf(newLog, "[%d-%02d-%02d %02d:%02d:%02d]", strtime->tm_year+1900, strtime->tm_mon+1, strtime->tm_mday, strtime->tm_hour, strtime->tm_min, strtime->tm_sec);
			}
			if((pid = fork()) <0)
			{
				exit(1);
			}
			else if(pid == 0)
			{
				execl("/bin/cp", "cp", logPath, newLog, NULL); //cp를 통하여 로그파일을 해당 시간정보의 이름으로 복사합니다.
			}
			else
			{
				wait(NULL);
			}
		}
		if(q_cnt > 0) // q에 대기중인 프로세스 정보가 담겨있다면
		{
			kill(queue[front], SIGUSR1); // 큐 맨 앞의 프로세스 정보에 대하여 작업허가 시그널을 전달하고
			front = (front + 1) % queuesize;
			--q_cnt;
		}
		else // 대기중인 큐가 없다면
		{
			is_Using = 0; // 관리 파일이 사용중이지 않다는 상태정보를 저장합니다.
		}
		close(fd); //파일 닫습니다.
	}
}
