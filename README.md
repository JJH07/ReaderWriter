# ReaderWriter

Linux에서 FIFO와 시그널로 파일 편집 순서를 관리하는 C 프로그램입니다. `ssu_ofm`이 편집 권한을 관리하고 `ssu_vim`이 파일을 읽거나 Vim으로 편집합니다.

## 유지해야 하는 원본 계약

기준은 원본 커밋 [`a2dbeb7`](https://github.com/JJH07/ReaderWriter/tree/a2dbeb73c1d2b5e7a58cf536b27dd4c40497d3e0)입니다.

1. 기존 동작과 입출력 명세를 변경하지 않습니다.
2. 사용자 기능을 추가하거나 제거하지 않습니다.
3. 빌드와 작동에 필요한 저장소 파일은 **`ssu_ofm.c`, `ssu_vim.c`, `Makefile` 세 개**입니다. 별도 공통 소스·헤더가 없습니다.

문서, 테스트, GitHub Actions는 개발·검증 자료이며 빌드와 실행에 필요하지 않습니다.

## 빌드와 실행

Linux, C 컴파일러, GNU Make, `ps`, `/bin/cat`, `/usr/bin/vim`, `/usr/bin/diff`, `/bin/cp`를 사용합니다.

```sh
make
printf 'hello\n' > sample.txt
./ssu_ofm sample.txt
./ssu_vim sample.txt -r
./ssu_vim sample.txt -w -t -s -d
./ssu_vim sample.txt -rw
```

데몬은 기본적으로 백그라운드에서 실행됩니다. 같은 작업 디렉터리에서 실행하고 파일명 문자열도 동일하게 지정합니다. 예를 들어 `sample.txt`와 `./sample.txt`를 자동으로 같은 요청으로 바꾸지 않습니다. 원본처럼 `ps -C ssu_ofm`으로 데몬을 찾으므로 실행 중인 관리 데몬 하나를 전제로 사용합니다. 종료하려면 로그 첫 줄의 PID에 `kill PID`를 실행합니다.

## 실행 옵션

```text
ssu_ofm FILE [-l] [-t] [-n N] [-p DIR] [-id]
ssu_vim FILE <-r|-w|-rw> [-t] [-s] [-d]
```

| 프로그램 | 옵션 | 원래 동작 |
| --- | --- | --- |
| ssu_ofm | `-l` | 편집 완료 시 로그 복사본 생성 |
| ssu_ofm | `-t` | 로그에 시간 표시 |
| ssu_ofm | `-n N` | 대기 큐 크기 지정. 기본 16, 별도 1024 제한 없음 |
| ssu_ofm | `-p DIR` | `./DIR/ssu_log.txt`에 기록 |
| ssu_ofm | `-id` | 요청 사용자의 이름·UID·GID 기록 |
| ssu_vim | `-r` | `/bin/cat`으로 읽기 |
| ssu_vim | `-w` | 권한을 기다린 후 `/usr/bin/vim`으로 편집 |
| ssu_vim | `-rw` | 읽은 후 수정 여부를 물어 `yes` 입력 시 편집 |
| ssu_vim | `-t` | 수정 시각과 변경 여부 표시 |
| ssu_vim | `-s` | 변경됐을 때 편집 전후 파일 크기 표시 |
| ssu_vim | `-d` | 변경됐을 때 원래 형식의 `diff` 결과 표시 |

클라이언트의 모드 옵션은 파일명 바로 뒤에 둡니다. `-rw`는 `yes` 이외의 답변이나 입력 종료 시 편집을 취소합니다. `-w`와 `-rw`는 데몬이 필요하며, `-rw`에서 취소할 계획이어도 데몬 확인을 먼저 합니다. `-r`에는 데몬이 필요하지 않습니다.

편집 권한 대기에는 시간 제한이 없습니다. 큐가 가득 찼을 때도 요청을 버리지 않고 기다립니다. `-n 0`은 대기 큐 없이 현재 편집이 끝나기를 기다립니다. 변경 여부는 원본처럼 초 단위 `st_mtime`으로 판정합니다. 같은 초 안에서 변경한 내용은 변경으로 판정되지 않을 수 있습니다.

`-f`, `--socket`, `--timeout`, `--help` 옵션과 `EDITOR`에 따른 편집기 선택은 제공하지 않습니다. 편집기는 원래의 `/usr/bin/vim`이며 `diff -u`로 출력 형식을 변경하지 않습니다.

## 출력과 생성 파일

원래의 주요 출력 문구를 유지합니다.

출력 버퍼링도 원본 방식으로 유지합니다. 터미널에서는 시간 정보가 먼저 보이지만, `./ssu_vim sample.txt -r -t > out.txt`처럼 리다이렉션하면 파일 내용 뒤에 시간 정보가 기록됩니다. 편집 결과를 리다이렉션할 때는 자식 프로세스인 Vim·diff의 출력이 부모의 보고 문구보다 먼저 기록될 수 있습니다. 출력 문구를 재정렬하는 별도 옵션은 없습니다.

```text
Daemon Process Initialization
Would you like to modify 'sample.txt'? (yes/no) :
Waiting for Token...
##[Modification Time]##
There was modification.
##[File Size]##
Before modification : 9(bytes)
After modification : 16(bytes)
##[Compare with Previous File]##
```

| 경로 | 용도 |
| --- | --- |
| `./tmp/fifo` | 파일명 전달 FIFO. 제어에는 `SIGUSR1`, `SIGUSR2` 사용 |
| `./ssu_log.txt` | 기본 로그 |
| `./DIR/ssu_log.txt` | `-p DIR` 사용 시 로그 |
| `[YYYY-MM-DD HH:MM:SS]` | `-l` 로그 복사본. `-p` 지정 시 해당 디렉터리에 생성 |
| `tempXXXXXX` 패턴 | 편집 전 비교용 임시 파일. 실제 이름을 생성하고 사용 후 삭제 |

로그 복사본 이름은 초 단위이므로 같은 초의 복사본은 원본처럼 덮어씁니다. 취소한 실행은 임시 파일을 삭제하지 않습니다.

## 검토 자료

- [수정 내역과 호환성 기준](docs/REVIEW_FIXES.md)
- [내부 처리 구조](docs/ARCHITECTURE.md)
- [검증 방법과 범위](docs/TESTING.md)
- [수정 규칙](CONTRIBUTING.md)
- [Linux CI](https://github.com/JJH07/ReaderWriter/actions/workflows/ci.yml)
