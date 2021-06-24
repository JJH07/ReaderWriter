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

#define BIT_r 1
#define BIT_w 2
#define BIT_rw 4
#define BIT_t 8
#define BIT_s 16
#define BIT_d 32
#define FIFO_FILE "./tmp/fifo" // fifo 파일 경로입니다.

int check_bit(int FLAG);
void parse(int argc, char *argv[]);
static void sig_usr(int signo, siginfo_t *si, ucontext_t *uc); // 시그널 받을 때 사용하는 함수입니다.
	
int FLAG_WAIT_SIGNAL = 1;
int bitset, temp_fd;

pid_t ofm; // ofm의 pid값이 저장될 변수입니다.
char *filename; // 수정하거나 읽을 파일 이름이 들어가는 변수입니다.
char tempfile[] = "tempXXXXXX";

int main(int argc, char *argv[])
{
	pid_t pid; // fork를 위한 변수입니다.
	int fifofd;

	int n; // 파일 내용 복사할 때 사용할 변수입니다.
	char buf[256]; // IO버퍼입니다.

	struct sigaction act; // sigaction함수를 사용하기 위한 구조체 변수입니다.
	sigset_t sig; // suspend사용을 위한 변수입니다.
	
	struct stat statbuf, statbuf2; // 파일 상태 정보를 얻기 위한 구조체 변수입니다.
	time_t rawTime; 
	struct tm *mtime, *now; //현재 시간 정보를 얻기 위한 변수들입니다.

	parse(argc, argv);

	act.sa_flags = SA_SIGINFO; // ***시그널 세팅을 위한 설정입니다.
	act.sa_sigaction = (void (*)(int, siginfo_t *, void *))sig_usr;// 
	sigemptyset(&act.sa_mask);//
	sigemptyset(&sig);//
	sigprocmask(SIG_BLOCK, &sig, NULL);//	

	if(sigaction(SIGUSR1, &act, (struct sigaction *)NULL) < 0)//
	{
		perror("sigaction(SIGUSR1)");
		exit(1);
	}
	if(sigaction(SIGUSR2, &act, (struct sigaction *)NULL) < 0)//
	{
		perror("sigaction(SIGUSR2)");
		exit(1);
	}	//****

	if(lstat(filename, &statbuf) < 0) //수정 이전에 대한 파일의 정보를 불러옵니다.
	{
		perror("lstat() error\n");
		exit(1);
	}
	
	if((bitset & BIT_r) == 0 && ofm == 0) // r옵션이 아니며 ssu_ofm를 실행하지 않았을 때
	{
		printf("where is ssu_ofm?\nssu_vim error\n"); //오류 출력
		exit(1); // 프로그램 종료
	}

	if(bitset & BIT_t) //t옵션 실행
	{
		mtime = localtime(&statbuf.st_mtime); //파일 수정시간을 저장합니다.
		time(&rawTime); //현재시간을 불러옵니다.
		now = localtime(&rawTime); //현재시간을 저장합니다.

		printf("##[Modification Time]##\n");
		printf("Last Modification time of '%s': [%d-%02d-%02d %02d:%02d:%02d]\n", filename, mtime->tm_year+1900, mtime->tm_mon+1, mtime->tm_mday, mtime->tm_hour, mtime->tm_min, mtime->tm_sec);
		printf("Current time: [%d-%02d-%02d %02d:%02d:%02d]\n", now->tm_year+1900, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
	}

	if(bitset & BIT_r) //r옵션일 때
	{
		if((pid = fork()) < 0) //fork를 실행하여
		{
			exit(1);
		}
		else if(pid == 0)
		{
			execl("/bin/cat", "cat", filename, NULL); //execl함수를 통해 파일 정보를 출력합니다.
		}
		else
		{
			wait(NULL);
			exit(0);
		}
	}
	else if(bitset & BIT_w) // -w -t 옵션일 때
	{	
		if((fifofd = open(FIFO_FILE, O_WRONLY)) < 0) // fifo파일을 열어서
		{
			printf("error in fifoopen\n");
			exit(1);
		}
		if((n = write(fifofd, filename, strlen(filename))) < 0) // 관리대상인 파일인지를 확인하기위해 fifo에 파일을 저장시키고
		{
			printf("write error in fifo write\n");
			exit(1);
		}
		close(fifofd);
		kill(ofm, SIGUSR1); // SIGUSR1을 전달하여 파일 수정 요청을 보냅니다.

		while(FLAG_WAIT_SIGNAL) // ofm으로부터 시그널을 받을 때까지 기다립니다. 출력 양식은 -t옵션 포함입니다.
		{
			printf("Waiting for Token...%s", filename);
			if(bitset & BIT_t)
			{
				time(&rawTime);
				now = localtime(&rawTime);
				printf("[%d-%02d-%02d %02d:%02d:%02d]", now->tm_year+1900, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
			}
			printf("\n");
			sleep(1);
		}
	}
	else if(bitset & BIT_rw) //-rw -t옵션일 때
	{
		if((pid = fork()) < 0)
		{
			exit(1);
		}
		else if(pid == 0)
		{
			execl("/bin/cat", "cat", filename, NULL); //-r 옵션에 대하여 먼저 실행
		}
		else
		{
			wait(NULL);
		}
		printf("\nWould you like to modify '%s'? (yes/no) : ", filename); //-w옵션 실행할건지 묻고
		scanf("%s", buf);
		if(strcmp(buf, "yes") == 0) // yes요청이면 -w 옵션에 대해서도 실행
		{
			if((fifofd = open(FIFO_FILE, O_WRONLY)) < 0) // -w -t옵션과 동일
			{
				printf("error in fifoopen\n");
				exit(1);
			}
			if((n = write(fifofd, filename, strlen(filename) + 1)) < 0)
			{
				printf("write error in fifo write\n");
				exit(1);
			}
			close(fifofd);
			
			kill(ofm, SIGUSR1);
			while(FLAG_WAIT_SIGNAL)
			{
				printf("Waiting for Token...%s", filename);
				if(bitset & BIT_t)
				{
					time(&rawTime);
					now = localtime(&rawTime);
					printf("[%d-%02d-%02d %02d:%02d:%02d]\n", now->tm_year+1900, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
				}
				sleep(1);
			}
		}
	}

	if(lstat(filename, &statbuf2) < 0) // 수정 이후의 파일 정보를 불러옵니다.
	{
		printf("lstat error\n");
		exit(1);
	}
	if(bitset & BIT_t)
	{
		printf("##[Modification Time]##\n");
		if(difftime(statbuf.st_mtime, statbuf2.st_mtime) == 0.0) //파일의 수정시간정보를 통하여 수정되었는지 검사하고
		{
			printf("There was no modification.\n"); //수정하지 않았다면 
		}
		else
		{
			printf("There was modification.\n"); // 수정하였다면
		}
	}

	if(bitset & BIT_s) // s옵션에 대하여 출력합니다.
	{
		if(difftime(statbuf.st_mtime, statbuf2.st_mtime) != 0.0) // 파일 수정이 되었을 때만 출력합니다.
		{
			printf("##[File Size]##\n");
			printf("Before modification : %ld(bytes)\n", statbuf.st_size); // 수정 이전 사이즈
			printf("After modification : %ld(bytes)\n", statbuf2.st_size); // 수정 이후 사이즈
		}
	}

	if(bitset & BIT_d) // d 옵션에 대하여 출력합니다.
	{
		if(difftime(statbuf.st_mtime, statbuf2.st_mtime) != 0.0) // 파일 수정이 되었을 때만 실행합니다.
		{
			printf("##[Compare with Previous File]##\n");
			if((pid = fork()) < 0)
			{
				printf("fork() error");
				exit(1);
			}
			else if(pid == 0)
			{
				execl("/usr/bin/diff", "diff", tempfile, filename, NULL); //diff명령어를 통화여 수정된 부분에 대하여 화면에 출력합니다.
			}
			else
			{
				wait(NULL);
			}
		}
	}
	unlink(tempfile);
	return 0;
}

int check_bit(int FLAG)
{
	return bitset & FLAG ? 1 : 0;
}
void parse(int argc, char *argv[])
{
	FILE *fp;
	char buf[256];

	fp = popen("ps -C ssu_ofm", "r"); // ofm의 PID를 얻기 위해 ps -C ssu_ofm을 popen합니다.
	fgets(buf, 255, fp); // ssu_ofm의 정보가 담긴 한줄을 buf에 저장합니다.
	fscanf(fp, "%d", &ofm); // 그 중 맨 앞의 값이 pid이므로 ofm에 저장합니다.
	pclose(fp); // 닫습니다.

	filename = argv[1];
	if(argc < 2 || strcmp(argv[2], "-r") != 0 && strcmp(argv[2], "-w") != 0 && strcmp(argv[2], "-rw") != 0)
	{
		perror("Read / Write option error. Available = < -r | -w | -rw >\n");
		exit(1);
	}
	for(int i = 2; i < argc; i++)
	{
		if(strcmp(argv[i], "-r") == 0)
		{
			bitset |= BIT_r;
		}
		else if(strcmp(argv[i], "-w") == 0)
		{
			bitset |= BIT_w;
		}
		else if(strcmp(argv[i], "-rw") == 0)
		{
			bitset |= BIT_rw;
		}
		else if(strcmp(argv[i], "-t") == 0)
		{
			bitset |= BIT_t;
		}
		else if(strcmp(argv[i], "-s") == 0)
		{
			bitset |= BIT_s;
		}
		else if(strcmp(argv[i], "-d") == 0)
		{
			bitset |= BIT_d;
		}
		else
		{
			perror("Option error. AVAILABLE = < [-r | -w | -rw] | -t | -s | -d >\n");
			exit(1);
		}
	}
	if(check_bit(BIT_r) + check_bit(BIT_w) + check_bit(BIT_rw) > 1)
	{
		perror("THERE IS MORE THAN 1 READ/WRITE OPTION.\n VALID = ONLY ONE OF < -r | -w | -rw >");
		exit(1);
	}
}
static void sig_usr(int signo, siginfo_t *si, ucontext_t *uc) //시그널이 들어오면 실행됩니다.
{
	pid_t pid;
	int n, origin_fd;
	char buf[256];
	
	temp_fd = mkstemp(tempfile);
	origin_fd = open(filename, O_RDONLY);
	while((n = read(origin_fd, buf, 256)) > 0)
	{
		write(temp_fd, buf, n);
	}
	close(origin_fd);

	if(signo == SIGUSR1) //SIGUSR1이 들어오면 파일 수정허가가 내려온 것이므로
	{
		if((pid = fork()) < 0)
		{
			perror("fork()");
			exit(1);
		}
		else if(pid == 0)
		{
			execl("/usr/bin/vim", "vim", filename, NULL); // vi 열고 실행합니다.
		}
		else
		{
			wait(NULL); // 기다렸다가 끝나면
			kill(ofm, SIGUSR2); // 종료되었음을 ofm에 SIGUSR2를 보내서 알립니다.
		}
	}
	else if(signo == SIGUSR2) // ofm의 관리 대상 파일과 vim에서 수정하려는 파일이 다를 때를 위해 임의로 설정한 부분입니다. SIGUSR2가 들어오면 관리대상 파일이 아니라는 뜻입니다.
	{
		printf("Can't Manage File(%s) : Incorrect ofm filename\n", filename); // 따라서 출력하고
		exit(1); // 종료합니다.
	}
	
	FLAG_WAIT_SIGNAL = 0;
}