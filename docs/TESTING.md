# 검증 방법

## 실행

Linux에서 실제 `/usr/bin/vim`을 포함한 원본 실행 도구를 준비합니다.

```sh
make
python3 -m unittest discover -s tests -v
```

테스트는 독립 임시 디렉터리에서 실행하며 해당 테스트의 데몬과 클라이언트만 종료합니다. 단일 데몬 검색 방식을 검증하므로 다른 `ssu_ofm`이 실행되지 않은 환경을 사용합니다. Vim의 기존 `VIMINIT` 기능으로 테스트용 입력을 자동화합니다. 제품에 테스트 전용 편집기 옵션이나 설정 파일을 추가하지 않습니다.

## 확인 범위

- 원래 세 파일만 별도 디렉터리에 복사해 `make` 성공, 추가 C 파일·헤더 없음
- 읽기 출력, 시각 표제와 값, 수정 확인 문구, 취소와 입력 종료
- 실제 Vim 편집, 전후 파일 크기, 원래 일반 diff 출력
- 변경 없는 경우의 출력, 원래 임시 파일명과 취소 시 사용자 파일 보존
- 원래 옵션과 기본 큐 16, 1024보다 큰 큐 값, 0 크기 큐
- 원래 FIFO 경로, 다른 파일명 거부 문구
- 큐가 가득 찬 경우, 죽은 대기자, 여러 동시 편집 요청
- FIFO 통지 후 종료된 요청자의 시그널이 후속 요청을 유실시키지 않는지 강제 실행 순서로 확인
- 큐 크기 1과 0에서 현재 편집이 끝나기 전 잘못된 파일명 거부: `-w`·`-rw`의 원래 문구·종료 코드, 원문 파일명 비교, 파일·로그 보존 및 이후 정상 대기 순서 확인
- 31초 이상 기다린 요청이 계속 대기하다 편집하는지 확인
- `-t -id -l -p` 조합의 로그 문구·사용자 정보·복사본 이름
- 누락·충돌 인자의 안전한 실패, 원본에 없는 옵션 거부
- FIFO 자리에 있던 일반 파일 보존
- 원본 클라이언트와 파일·파이프 출력 비교: `-r -t`, `-rw -t` 취소, `-w/-rw -t -s -d` 실제 편집의 출력 순서
- 가상 터미널에서 원본과 읽기 출력 비교 및 답을 입력하기 전 수정 확인 문구 표시 검사
- 표준 입력·오류가 닫힌 환경에서 데몬의 정상 시작, 원래 초기화 문구 및 후속 실제 편집·완료 로그 확인
- 허용 한계인 497바이트 로그 디렉터리에서 `-l -p` 편집 완료 후 원래 날짜 이름의 복사본 생성 및 로그 내용 일치 확인
- 프로세스 목록의 첫 PID가 이미 사라진 경우 뒤의 실제 데몬을 선택하여 Vim 편집과 요청·완료 로그가 정상 작동하는지 확인
- 초기 로그 쓰기 실패 시 시작 실패 문구·종료 코드·파일 보존·정상 재시작 검사 및 표준 출력이 닫힌 정상 시작·편집 검사
- 편집 권한 대기 중 데몬이 좀비 상태가 되면 클라이언트가 실패 종료하고 파일을 보존하는지 검사; 살아 있는 데몬의 31초 이상 대기 검사도 유지
- `SIGCHLD` 무시 설정을 물려받은 클라이언트의 `-r`·`-w`·`-rw` 성공 종료, 실제 편집·보고·diff·완료 로그·임시 파일 정리 확인
- FIFO 경로 검사 직후 일반 파일로 교체되는 실행 순서를 고정하여 초기화 실패 응답·준비 완료 로그 미생성·일반 파일과 편집 대상 보존 확인
- 편집 래퍼만 강제 종료된 경우 실제 Vim의 잠금 유지, 후속 편집 대기, Vim 종료 후 순차 편집·파일 내용·완료 로그 순서 확인
- Vim이 저장 전에 오류 종료하거나 강제 종료되면 클라이언트의 실패 코드·수정 결과 보고 생략·임시 파일 정리·대기 중인 다음 편집의 정상 진행 확인
- 편집 전 임시 복사본 쓰기 실패 시 Vim 미실행·실패 코드·수정 결과 보고 생략·대상 파일 보존·임시 파일 정리·후속 요청 진행과 완료 로그 순서 확인
- 저장 후 실제 diff가 비교 오류로 종료하면 클라이언트의 실패 코드·저장 내용과 기존 보고 유지·임시 경로 정리·후속 편집 진행 및 완료 로그 순서 확인

## CI

2026-11-16 후속 검토 14번 검증 보강: 커밋 `6ff4b7017d2b60380fdc0a028d6e591c5ca7d8f0`에서 기존 39개와 diff 비교 오류 검사 1개를 합한 40개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43832940920). 검사한 오류 경로에서 새 제품 결함은 재현되지 않았으며 제품 코드는 변경하지 않았습니다.

2026-11-16 후속 검토 13번 검증 보강: 커밋 `590a9bba45439af4332adc0c3be2cf88a6d7f886`에서 기존 38개와 임시 복사본 쓰기 실패 검사 1개를 합한 39개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43831677584). 검사한 오류 반환 경로에서 새 제품 결함은 재현되지 않았으며 제품 코드는 변경하지 않았습니다.

2026-11-16 후속 검토 12번 검증 보강: 커밋 `416afe8ef2a830bf4dac70b6168125c68f67970a`에서 기존 37개와 편집기 실패 검사 1개(오류 종료·시그널 종료)를 합한 38개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43777807347). [첫 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43777519480)의 GCC에서는 이전 검사가 테스트용 PID 파일의 기록 완료 전에 읽어 실패했습니다. 테스트의 시작 알림 파일을 완성 후 이름 변경하는 방식으로 수정했으며 제품 코드는 변경하지 않았습니다.

2026-11-16 후속 검토 11번 검증 보강: 커밋 `e5ba6fb3d747f77faf0f7c647de995933285deda`에서 기존 36개와 편집 래퍼 종료 검사 1개를 합한 37개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43776804472). 제품 코드는 변경하지 않았으며 이 경로의 새 결함은 재현되지 않았습니다.

2026-11-16 후속 리뷰 10번 수정: 커밋 `455d4a6f190595ec4a96c204d849cad178288010`에서 기존 35개와 FIFO 검사·열기 사이 파일 교체 검사 1개를 합한 36개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43775875395). [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43775842430)에서는 세 구성 모두 새 검사만 잘못된 시작 성공으로 실패했습니다.

2026-11-15 후속 리뷰 9번 수정: 커밋 `9157cae5c04f7ea7df5b27bea272d65107b1bb64`에서 기존 34개와 상속된 `SIGCHLD` 무시 검사 1개를 합한 35개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43690805137). [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43690771625)에서는 세 구성 모두 새 검사의 `-r`·`-w`·`-rw` 하위 검사 세 개만 실패했습니다.

2026-11-15 후속 리뷰 8번 수정: 커밋 `ebc1c94546118a1e90c38207ec198f9d5cc102cc`에서 기존 33개와 좀비 데몬 대기 검사 1개를 합한 34개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43690158818). [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43690114946)에서는 세 구성 모두 새 검사만 대기 시간 초과로 실패했습니다.

2026-11-15 후속 리뷰 7번 재개 확인: 커밋 `18e30ecd64972e359f6def7ea44c42f5c5c116c7`에서 기존 31개와 초기 로그 쓰기 실패·표준 출력 닫힘 검사 2개를 합한 33개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43590715814). [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43590770589)에서는 세 구성 모두 초기 로그 쓰기 실패를 시작 성공으로 보고하는 검사만 실패했습니다.

2026-11-14 후속 리뷰 6번 수정: 커밋 `98d28a2f93f1c6030f66f489203208314b0e246b`에서 기존 30개와 사라진 PID 탐색 검사 1개를 합한 31개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43588382722). [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43588346272)에서는 세 구성 모두 새 검사만 편집 실패로 끝났습니다.

2026-11-14 후속 리뷰 5번 수정: 커밋 `fceeafeabbfd66b071e5b81488241a6765ea9357`에서 기존 29개와 긴 로그 디렉터리 검사 1개를 합한 30개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43587452295). [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43587412447)에서는 세 구성 모두 새 복사본 생성 검사만 시간 초과했습니다.

2026-11-14 후속 리뷰 4번 수정: 커밋 `2a62b61a32d76d7d9f92910fbc478778dbbb3df5`에서 기존 28개와 닫힌 표준 스트림 시작 검사 1개를 합한 29개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43586822364). [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43586790476)에서는 세 구성 모두 새 검사만 실패했습니다.

2026-11-14 후속 리뷰 3번 수정: 커밋 `aecff7bf5fa82b2421f52ed6af19dc0ff4256075`에서 28개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43586224057). 기존 24개 검사 중 출력 순서 기대값 두 곳을 원본에 맞추고, 원본 클라이언트와 비교하는 네 검사를 추가했습니다. 같은 테스트의 [수정 전 실행](https://github.com/JJH07/ReaderWriter/actions/runs/43586242958)은 세 구성 모두 출력 순서 관련 10개 단언에서 실패하여 회귀 검출도 확인했습니다.

2026-11-14 후속 리뷰 2번 수정: 커밋 `409f83375ed461538e8a490d4545616a177ec2b5`에서 24개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/43533025588). 기존 22개 검사와 두 큐 용량에 대한 새 검사이며, 각 새 검사 안에서 `-w`·`-rw`와 두 파일명 경우를 모두 확인합니다. 3번 리뷰 항목인 리다이렉션 출력 순서는 이번 수정 범위에서 제외합니다.

후속 리뷰 1번 수정: 커밋 `500c667ba7cbf41d3367a3b43223ca8ef9421b32`의 22개 테스트가 GCC·Clang·GCC + ASan/UBSan 모두 통과했습니다. [2026-11-08 실행 결과](https://github.com/JJH07/ReaderWriter/actions/runs/42432895043)를 2026-11-14 작업 재개 시 다시 확인했습니다. 새 요청 유실 재현 테스트와 기존 21개 테스트를 포함합니다. 동시 요청 테스트는 실제 Vim 여섯 번의 순차 실행을 기다릴 수 있도록 테스트용 제한 시간만 조정했으며, 제품의 대기 정책은 변경하지 않았습니다.

2026-11-08 검증: 실행 코드 커밋 `de8f326399b7d01b9a4c0808dcf44de5cfc88fec`의 21개 테스트가 세 구성 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/42431232860)

[Linux build and integration tests](https://github.com/JJH07/ReaderWriter/actions/workflows/ci.yml)는 GCC, Clang, GCC + AddressSanitizer/UndefinedBehaviorSanitizer 세 구성에서 같은 테스트를 실행합니다. `-Wall -Wextra -Wpedantic -Werror`로 컴파일합니다.

Windows 로컬 환경의 정적 확인과 Linux CI의 실제 실행 결과를 구분합니다. Sanitizer 통과는 실행한 경로에 대한 검사이며 모든 스케줄링·파일시스템·강제 종료 상황에 대한 증명은 아닙니다. 원본 바이너리와의 전 입력 자동 대조 검사는 포함하지 않습니다.

`test_output_order.py`는 Git 이력의 원본 `ssu_vim.c`를 수정 없이 별도 임시 디렉터리에서 GCC로 빌드합니다. CI는 이를 위해 원본 커밋을 포함한 이력을 가져옵니다. 출력 순서 비교에서 날짜·시각 문자열은 치환하며, 원본의 시각 계산 버그는 재도입하지 않습니다. 현재 코드의 실제 수정 시각 값은 별도 통합 테스트로 검사합니다. 편집 테스트는 같은 실제 데몬·Vim을 사용하되 원본이 이전 테스트의 좀비 PID를 선택하지 않도록 테스트 환경의 `ps` 결과를 해당 데몬 하나로 고정합니다. 편집기의 화면 제어 문자열과 대기 횟수는 전체 바이트 비교 대상이 아니며, 출력 표제와 결과의 상대 순서를 검사합니다. 원본의 알려진 메모리·시그널 문제 때문에 원본 바이너리는 sanitizer 대상에서 제외하고 현재 제품 코드를 검사합니다.
