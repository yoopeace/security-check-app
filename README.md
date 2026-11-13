# 보안 점검 도구 (Security Check)

[![CI](https://github.com/yoopeace/security-check-app/actions/workflows/ci.yml/badge.svg)](https://github.com/yoopeace/security-check-app/actions/workflows/ci.yml)

윈도우 업무용 PC에서 인터넷 없이 쓰는 보안 점검 데스크톱 앱 (개발 중).

- 로그 분석: 윈도우 보안 이벤트 로그(`.evtx`)에서 로그인 반복 실패, 로그 삭제, 계정 변경 탐지
- 파일 무결성 검사: 폴더의 기준선을 만들고 변조·삭제·추가 여부 확인

탐지 로직은 [log-analyzer](https://github.com/yoopeace/log-analyzer)와
[file-integrity-checker](https://github.com/yoopeace/file-integrity-checker)를 그대로 불러 씀.

설계: [docs/superpowers/specs/2026-11-13-windows-desktop-app-design.md](docs/superpowers/specs/2026-11-13-windows-desktop-app-design.md)
