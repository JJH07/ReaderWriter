# 코드 리뷰 대응 내역

검토 기준은 원본 커밋 [`a2dbeb7`](https://github.com/JJH07/ReaderWriter/tree/a2dbeb73c1d2b5e7a58cf536b27dd4c40497d3e0)입니다. 수정 코드와 함께 [통합 테스트](../tests/test_integration.py)를 추가했습니다.

| 리뷰에서 확인한 문제 | 변경 사항 | 회귀 검증 |
| --- | --- | --- |
| `-rw` 취소 시 `tempXXXXXX`라는 기존 파일 삭제 | 취소는 즉시 반환. 스냅샷 생성 성공 시에만 정리 | `test_cancel_preserves_literal_temp_name_and_target` |
| `mkdir(..., 0666)`로 처음 실행할 때 FIFO 생성 실패 | 소켓 디렉터리를 `0700`으로 생성하고 기존 경로 검증 | `test_cold_start_permissions_and_edit_report`, `test_non_traversable_socket_directory_is_reported` |
| 초기화하지 않은 `fd`를 `close()` | 소유권이 명확한 연결·파일 FD로 분리하고 유효한 경우만 닫기 | GCC·Clang `-Werror`, ASan/UBSan 및 전체 통합 테스트 |
| FIFO 데이터와 시그널 PID의 대응 실패, 요청 경계 손실 | 연결별 고정 요청 패킷, `SOCK_SEQPACKET`, 길이·magic·NUL 검증 | `test_burst_requests_are_framed_and_ordered`, `test_malformed_packets_do_not_break_server` |
| 시그널 핸들러 재진입에 따른 큐 갱신 충돌 | 단일 poll 이벤트 루프. 종료 핸들러는 플래그만 설정 | `test_parallel_editors_never_overlap`, 종료·대기자 테스트 |
| 종료된 대기자에게 권한을 넘긴 뒤 영구 대기 | 연결 해제 감지, 전송 실패한 대기자 제거 | `test_disconnected_waiter_does_not_block_successor` |
| 대기열 포화 요청을 응답 없이 버림 | BUSY 응답 및 클라이언트 오류 종료 | `test_queue_full_is_explicit` |
| 인자 부족으로 NULL 포인터 접근 | 파일명·모드·옵션 인자 수와 숫자 범위 검증 | `test_missing_and_conflicting_arguments` |
| 무제한 `%s` 확인 입력 | 길이가 제한된 `fgets()`와 yes/no 값 검사 | `test_long_confirmation_is_rejected` |
| `localtime()` 정적 버퍼 재사용으로 시간 표시 오류 | 각 출력에서 `localtime_r()` 사용 | `test_read_without_daemon_and_correct_timestamp` |

## 함께 보완한 동작

- 파일 수정 시간만 비교하던 방식에서 **스냅샷과 실제 내용 비교**로 변경했습니다. 같은 타임스탬프를 유지한 수정도 감지합니다.
- 편집기 실행 실패, 스냅샷 생성 실패, 연결 종료를 오류로 처리하고 자원을 정리합니다. `exec` 실패 자식은 `_exit()`로 끝납니다.
- 완료 후 크기·diff 출력까지 편집 권한을 유지해 다음 편집자의 변경이 결과에 섞이는 것을 줄였습니다.
- 요청 대기에 기본 30초 제한을 두고 `--timeout`으로 조절할 수 있게 했습니다.
- 백그라운드 시작은 초기화 결과를 부모에게 전달한 뒤 성공을 출력합니다. `-f`로 포그라운드 실행도 가능합니다.
- Makefile을 파일별 의존성 기반으로 정리하고 `test`, `sanitize`, `clean` 타깃을 추가했습니다.
- `.gitignore`, `.gitattributes`, Linux CI 및 한국어 사용·설계 문서를 추가했습니다.

## 호환성 변경

기존 실행 파일 이름과 `-r`, `-w`, `-rw`, `-t`, `-s`, `-d`, `-l`, `-n`, `-p`, `-id` 옵션은 유지합니다. 다음은 달라졌습니다.

- 통신 경로는 `./tmp/fifo`에서 `./tmp/readerwriter.sock`으로 바뀌었습니다. 기존 FIFO 및 SIGUSR1/SIGUSR2 요청은 처리하지 않습니다.
- 로그 사본 이름은 초 단위 시각 대신 충돌하지 않는 임의 접미사를 사용합니다.
- `-rw` 취소는 데몬이 없어도 가능합니다. 큐 포화와 잘못된 대상 파일은 오류로 즉시 응답합니다.
- 읽기는 원래처럼 데몬과 무관하게 수행합니다. 읽기까지 편집과 배타적으로 막는 기능은 추가하지 않았습니다.

자동 테스트는 구현한 시나리오의 검증이며 모든 실행 환경과 편집기의 동작을 보장하지 않습니다. 지원 범위는 [README](../README.md#사용-범위와-제약)에 명시했습니다.
