# 테스트 자료

| 파일 | 내용 | 출처 |
|------|------|------|
| `security.evtx` | 윈도우 보안 로그 2,261건 (4624·4720·4732 포함, 4625 없음) | [python-evtx](https://github.com/williballenthin/python-evtx) `tests/data` (Apache-2.0). 원 제공: Carlos Dias |
| `system.evtx` | 윈도우 시스템 로그 1,601건 (보안 로그가 아님) | python-evtx `tests/data` (Apache-2.0). 원 출처: [plaso](https://github.com/log2timeline/plaso) test_data (Apache-2.0) |
| `dns_log_malformed.evtx` | 기록 5건 중 4건이 깨진 DNS 서버 로그 | python-evtx `tests/data` (Apache-2.0). 원 제공: python-evtx issue #37 |
| `not_evtx.evtx` | 확장자만 `.evtx`인 텍스트 파일 | 이 저장소에서 작성 |

공개 저장소에 이미 공개된 실습용 로그만 사용함. 실제 업무 PC나 개인 PC의 로그는 넣지 않음.
