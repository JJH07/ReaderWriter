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
- 31초 이상 기다린 요청이 계속 대기하다 편집하는지 확인
- `-t -id -l -p` 조합의 로그 문구·사용자 정보·복사본 이름
- 누락·충돌 인자의 안전한 실패, 원본에 없는 옵션 거부
- FIFO 자리에 있던 일반 파일 보존

## CI

2026-11-08 검증: 실행 코드 커밋 `de8f326399b7d01b9a4c0808dcf44de5cfc88fec`의 21개 테스트가 세 구성 모두 통과했습니다. [검증 실행 기록](https://github.com/JJH07/ReaderWriter/actions/runs/42431232860)

[Linux build and integration tests](https://github.com/JJH07/ReaderWriter/actions/workflows/ci.yml)는 GCC, Clang, GCC + AddressSanitizer/UndefinedBehaviorSanitizer 세 구성에서 같은 테스트를 실행합니다. `-Wall -Wextra -Wpedantic -Werror`로 컴파일합니다.

Windows 로컬 환경의 정적 확인과 Linux CI의 실제 실행 결과를 구분합니다. Sanitizer 통과는 실행한 경로에 대한 검사이며 모든 스케줄링·파일시스템·강제 종료 상황에 대한 증명은 아닙니다. 원본 바이너리와의 전 입력 자동 대조 검사는 포함하지 않습니다. 기대 출력은 원본 코드의 문구와 기능을 기준으로 작성했습니다.
