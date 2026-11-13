# 보안 점검 데스크톱 앱 (윈도우) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 기존 두 도구(log-analyzer, file-integrity-checker)를 불러 쓰는, 인터넷 없이 도는 윈도우 데스크톱 앱 `SecurityCheck.exe`를 만든다.

**Architecture:** 기존 두 저장소는 판정 로직의 원본으로 남기고, 값으로 결과를 돌려주는 함수만 보강한 뒤 버전 태그를 붙인 패키지로 만든다.
새 저장소 `security-check-app`은 윈도우 이벤트 로그 해석(`winevents`), 판정(`log_check`, `integrity_check`), 보고서 문장(`report_text`),
화면(`app`)으로 나누고, 화면을 뺀 모든 모듈은 값으로 테스트한다. 실행 파일은 GitHub Actions 윈도우 환경에서 PyInstaller로 만든다.

**Tech Stack:** Python 3.12, CustomTkinter 6.x (MIT), python-evtx 0.8.x (Apache-2.0, 의존: hexdump), PyInstaller 6.x, pytest, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-11-13-windows-desktop-app-design.md`

## Global Constraints

- 실행 파일은 인터넷 없이 동작한다. 네트워크를 쓰는 코드는 넣지 않는다.
- 대상: 윈도우 10·11. 개발·테스트는 맥에서도 돌아야 한다 (윈도우 전용 기능은 윈도우가 아니면 "지원 안 함"으로 처리).
- 분석 대상 `.evtx` 파일과 검사 대상 폴더에는 아무것도 쓰지 않는다. 앱이 쓰는 파일은 `%LOCALAPPDATA%\SecurityCheck\` 아래에만 둔다 (윈도우가 아니면 `~/.security-check/`).
- 판정은 세 가지뿐: `위험 발견` / `확인 필요` / `이상 없음`. 화면 문구에 해시, 종료 코드, SHA-256 같은 말을 쓰지 않는다.
- 읽지 못한 부분이 있거나 근거가 없으면 절대 `이상 없음`이 아니다.
- 기존 두 도구의 터미널 출력과 종료 코드는 바뀌지 않는다 (log-analyzer 20개, checker 30개 시나리오 비교 스크립트로 확인).
- 창 제목 `보안 점검 도구`, 실행 파일 `SecurityCheck.exe`, 글꼴 맑은 고딕(`Malgun Gothic`), 밝은 화면 고정.
- 커밋은 각 저장소 main 에 직접, 한국어 메시지. 소스에는 보이지 않는 문자를 직접 쓰지 않고 `\uXXXX` 이스케이프로 쓴다 (커밋 전 검사).

## Review Focus

1. **보안 로그가 아닌 `.evtx`, 또는 확장자만 `.evtx`인 다른 파일**: 앱이 꺼지지 않고 `확인 필요` + "보안 로그가 아닙니다" 또는 "읽을 수 없는 파일입니다". → Task 6, Task 7
2. **로그인 실패 기록의 IP가 `-`이고 계정 이름도 `-`·빈 값**: `계정 (알 수 없음)`으로 묶여 판정된다. → Task 6
3. **이미 기준선이 있는 폴더에서 [기준선 만들기]를 다시 누름**: 변조 후 기준선을 새로 만들면 변조가 정상으로 기록되므로, 덮어쓰기 전에 확인을 받는다 (`replace=False`면 거부). → Task 8
4. **기준선을 만든 적 없는 폴더(또는 이름이 바뀐 폴더)에서 [검사하기]**: `확인 필요` + "이 폴더의 기준선이 없습니다. 먼저 기준선을 만들어 주세요." → Task 8
5. **같은 앱에서 여러 폴더를 차례로 검사**: 검사 기록이 각 폴더의 기록 파일에 따로 쌓인다 (`logging.basicConfig`는 한 번만 적용되므로 쓰지 않는다). → Task 8

---

## 1부. 기존 도구 보강

### Task 1: log-analyzer — 판정 함수 떼어 내기

**Files:**
- Modify: `/Users/peaceyoo/log-analyzer/log_analyzer.py` (`analyze()` 부근)
- Test: `/Users/peaceyoo/log-analyzer/test_log_analyzer.py` (9절)

**Interfaces:**
- Produces: `judge_failures(fail_events: list[tuple[datetime | None, str]], tiers=DEFAULT_TIERS) -> list[BruteforceAlert]` — 등급 순서대로 `detect_bruteforce`를 돌리고 같은 키는 가장 앞 등급만 남긴다. 키(`BruteforceAlert.ip` 자리)는 IP가 아닌 아무 문자열이어도 된다.
- `analyze()`는 이 함수를 써서 지금과 같은 결과를 낸다.

- [ ] **Step 1: 실패하는 테스트**

```python
def test_판정은_실패_이벤트_목록만으로도_할_수_있다():
    events = [(ts(f"2024-01-15 09:00:{i:02d}"), '계정 admin') for i in range(8)]
    alerts = judge_failures(events)
    assert [(a.ip, a.tier) for a in alerts] == [('계정 admin', '누적')]

def test_analyze와_judge_failures는_같은_판정을_한다():
    lines = burst('198.51.100.7', FAST_TIER.threshold) + spread('203.0.113.7', SLOW_TIER.threshold, 30)
    fail_events, _ = scan_log(iter(lines))
    assert analyze(lines).brute_alerts == judge_failures(fail_events)
```

- [ ] **Step 2:** `.venv/bin/pytest -q` → ImportError `judge_failures`
- [ ] **Step 3:** `judge_failures` 구현, `analyze()`의 묶기 반복문을 이 함수 호출로 교체
- [ ] **Step 4:** `.venv/bin/pytest -q` 전부 통과, `la_golden.sh` 20개 시나리오 동일
- [ ] **Step 5:** 커밋 `판정 함수 judge_failures 분리 (앱에서 재사용)`

### Task 2: checker — 기준선 만들기도 결과를 값으로

**Files:**
- Modify: `/Users/peaceyoo/Desktop/checker/checker.py:434-480` (`create_snapshot`)
- Test: `/Users/peaceyoo/Desktop/checker/test_checker.py` (5절)

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) SnapshotOutcome(failure: str | None, detail: object = None, saved_count: int = 0, key_created: bool = False)`
    - `failure`: `None`(성공) / `"target_missing"` / `"scan_incomplete"`(detail: 실패 dict) / `"key_unavailable"`(detail: `KeyUnavailable`) / `"save_failed"`(detail: `OSError`)
    - `exit_code` 속성: 성공 0, target_missing 2, scan_incomplete 4, key_unavailable 3, save_failed 2
  - `make_snapshot(directory, exclude_dirs=(), tool_files=None) -> SnapshotOutcome` (화면 출력 없음, 기록 로그만)
  - `print_snapshot_outcome(outcome, directory, tool_files) -> None`
  - `create_snapshot(...)`는 두 함수를 부르고 `exit_code`를 돌려주는 얇은 함수가 된다.

- [ ] **Step 1: 실패하는 테스트** (각 경우 한 건씩, 출력 없이 값만)

```python
def test_기준선_만들기는_결과를_값으로_돌려준다(tmp_path, capsys):
    docs = make_docs(tmp_path, {"a.txt": "내용"})
    outcome = checker.make_snapshot(str(docs), tool_files=tool_files_in(tmp_path))
    assert outcome == checker.SnapshotOutcome(None, saved_count=1, key_created=True)
    assert capsys.readouterr().out == ""

def test_없는_폴더면_target_missing(tmp_path):
    outcome = checker.make_snapshot(str(tmp_path / "없음"), tool_files=tool_files_in(tmp_path))
    assert (outcome.failure, outcome.exit_code) == ("target_missing", 2)
# scan_incomplete(권한 0o000 파일) → exit_code 4, detail 에 파일 이름
# save_failed(스냅샷 경로를 없는 폴더 안으로) → exit_code 2
```

- [ ] **Step 2:** `.venv/bin/pytest -q` → AttributeError `make_snapshot`
- [ ] **Step 3:** 구현. 화면 문구는 지금 `create_snapshot`의 print 를 그대로 `print_snapshot_outcome`으로 옮긴다.
- [ ] **Step 4:** 전체 테스트 통과, `checker_scenarios.sh` 30개 동일
- [ ] **Step 5:** 커밋 `기준선 만들기도 결과를 값으로 돌려주고 출력은 한 곳에서`

### Task 3: 두 도구를 설치 가능한 패키지로 만들고 태그

**Files:**
- Create: `/Users/peaceyoo/log-analyzer/pyproject.toml`, `/Users/peaceyoo/Desktop/checker/pyproject.toml`
- Modify: 두 README "설치" 한 줄

**Interfaces:**
- Produces: `pip install "log-analyzer @ git+https://github.com/yoopeace/log-analyzer@v1.0.0"` → `import log_analyzer`,
  `pip install "file-integrity-checker @ git+https://github.com/yoopeace/file-integrity-checker@v1.0.0"` → `import checker`

- [ ] **Step 1:** pyproject 작성 — setuptools 백엔드, `py-modules = ["log_analyzer"]` / `["checker"]`, `requires-python = ">=3.10"`, 의존성 없음, `license = "MIT"`
- [ ] **Step 2:** 확인: 임시 venv 에서 `pip install /Users/peaceyoo/log-analyzer` 후 `python -c "import log_analyzer; print(log_analyzer.judge_failures)"` 성공 (checker 도 같은 방식, `make_snapshot`)
- [ ] **Step 3:** 테스트 전체 통과 확인, `.gitignore`에 `build/`, `*.egg-info/` 추가
- [ ] **Step 4:** 커밋·push, `git tag v1.0.0` 후 `git push origin v1.0.0` (두 저장소 각각), CI 통과 확인

## 2부. 앱 저장소

### Task 4: 저장소 뼈대와 판정 값

**Files:**
- Create: `/Users/peaceyoo/security-check-app/` (git init, GitHub `yoopeace/security-check-app` 공개 저장소)
- Create: `seccheck/__init__.py`, `seccheck/verdict.py`, `tests/test_verdict.py`
- Create: `requirements.txt`, `requirements-dev.txt`, `.gitignore`, `pytest.ini`, `LICENSE`(MIT), `.github/workflows/ci.yml`
- Move: 설계 문서와 이 계획을 `docs/superpowers/specs/`, `docs/superpowers/plans/`로 (log-analyzer 쪽 사본은 지움)

**Interfaces:**
- Produces (`seccheck/verdict.py`):
  - `class Level(IntEnum)`: `OK = 0`, `CHECK = 1`, `DANGER = 2`; `Level.label` → `"이상 없음"` / `"확인 필요"` / `"위험 발견"`
  - `@dataclass(frozen=True) Finding(level: Level, message: str)`
  - `overall(findings: list[Finding]) -> Level` — 가장 높은 단계, 비어 있으면 `OK`

- [ ] **Step 1:** 테스트: `overall([]) == Level.OK`, `overall([Finding(CHECK,..), Finding(DANGER,..)]) == Level.DANGER`, 세 `label` 문구
- [ ] **Step 2:** 실패 확인 → **Step 3:** 구현 → **Step 4:** 통과
- [ ] **Step 5:** `requirements.txt`: `customtkinter>=6,<7`, `python-evtx>=0.8,<0.9`, Task 3 의 두 git 태그 줄. `requirements-dev.txt`: `-r requirements.txt`, `pytest`, `pyinstaller>=6,<7`
- [ ] **Step 6:** CI: `ubuntu-latest`, `windows-latest` 에서 Python 3.12, `pip install -r requirements-dev.txt`, `pytest -v`
- [ ] **Step 7:** 커밋·push, CI 통과 확인

### Task 5: 윈도우 이벤트 XML 해석

**Files:**
- Create: `seccheck/winevents.py`, `tests/test_winevents.py`, `tests/xml_samples.py`(테스트용 이벤트 XML 문자열 생성 도우미)

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) WinEvent(event_id: int, time_utc: datetime, channel: str, data: dict[str, str])` — `time_utc`는 UTC tzinfo 포함
  - `parse_event_xml(xml: str) -> WinEvent` — `System/EventID`, `System/TimeCreated@SystemTime`, `System/Channel`, `EventData/Data[@Name]` 그리고 `UserData` 아래 첫 요소의 자식들을 `data`에 담는다. 네임스페이스 `http://schemas.microsoft.com/win/2004/08/events/event`. 표준 `xml.etree.ElementTree` 사용.
  - `class EventParseError(ValueError)` — 필수 항목이 없거나 XML 이 깨졌을 때
  - `@dataclass(frozen=True) EvtxRead(events: list[WinEvent], total: int, unreadable: int, channels: frozenset[str])` — 파일 하나를 읽은 결과 (Task 7 이 채우고 Task 6 이 판정; 테스트에서는 직접 만든다)

- [ ] **Step 1: 테스트**

```python
def test_로그인_실패_이벤트를_읽는다():
    e = parse_event_xml(event_xml(4625, "2026-11-13T01:02:03.1234567Z",
                                  {"TargetUserName": "admin", "IpAddress": "10.0.0.5", "LogonType": "3"}))
    assert e.event_id == 4625
    assert e.time_utc == datetime(2026, 11, 13, 1, 2, 3, 123456, tzinfo=timezone.utc)
    assert e.channel == "Security"
    assert e.data["IpAddress"] == "10.0.0.5"

def test_로그_삭제_이벤트는_UserData에서_읽는다():
    e = parse_event_xml(user_data_xml(1102, "2026-11-13T02:00:00Z", "LogFileCleared", {"SubjectUserName": "kim"}))
    assert e.data["SubjectUserName"] == "kim"

def test_깨진_XML은_EventParseError():
    with pytest.raises(EventParseError):
        parse_event_xml("<Event><System>")
```

- [ ] **Step 2–4:** 실패 확인 → 구현 → 통과
- [ ] **Step 5:** 커밋

### Task 6: 로그 판정 규칙

**Files:**
- Create: `seccheck/log_check.py`, `tests/test_log_check.py`

**Interfaces:**
- Consumes: `WinEvent`, `EvtxRead`, `Finding`, `Level`, `overall`, `log_analyzer.judge_failures`, `log_analyzer.DEFAULT_TIERS`
- Produces:
  - `failure_key(data: dict[str, str]) -> str` — `IpAddress`가 `""`, `"-"`, `"127.0.0.1"`, `"::1"`이 아니면 그 IP, 아니면 `f"계정 {이름}"` (이름이 `""`·`"-"`면 `"계정 (알 수 없음)"`)
  - `KST = timezone(timedelta(hours=9))`
  - `@dataclass(frozen=True) LogReport(level: Level, findings: list[Finding], total: int, period: tuple[datetime, datetime] | None)` (period 는 KST)
  - `check_events(read: EvtxRead, tiers=DEFAULT_TIERS) -> LogReport`

- 규칙 (설계 7-3절):

| 조건 | Finding |
|---|---|
| `judge_failures` 경고 1건마다 | DANGER `"로그인 반복 실패(급속): 10.0.0.5 — 10분 안에 45회 (2026-11-13 10:02 ~ 10:05)"` |
| 1102 | DANGER `"보안 로그가 삭제되었습니다: 2026-11-13 11:00 (삭제한 계정: kim)"` |
| 4740 | CHECK `"계정이 잠겼습니다: admin"` |
| 4720 | CHECK `"새 계정이 만들어졌습니다: guest2"` |
| 4732 이고 `TargetSid == "S-1-5-32-544"` | CHECK `"관리자 그룹에 계정이 추가되었습니다: <MemberName 또는 MemberSid>"` |
| `"Security"` 가 channels 에 없음 | CHECK `"보안 로그가 아닙니다. 이벤트 뷰어의 '보안' 로그를 저장한 파일인지 확인해 주세요."` |
| 보안 로그인데 위 이벤트와 4625 가 하나도 없음 | CHECK `"분석할 로그인 기록이 없습니다. 감사 정책이 꺼져 있을 수 있습니다."` |
| `unreadable > 0` | CHECK `"읽지 못한 기록이 N건 있습니다."` |

- [ ] **Step 1: 테스트** — 표의 각 줄 한 건씩, 그리고:

```python
def test_이_PC_자신에서_온_실패는_계정별로_센다():
    assert failure_key({"IpAddress": "-", "TargetUserName": "admin"}) == "계정 admin"
    assert failure_key({"IpAddress": "::1", "TargetUserName": "-"}) == "계정 (알 수 없음)"
    assert failure_key({"IpAddress": "10.0.0.5", "TargetUserName": "admin"}) == "10.0.0.5"

def test_문제가_없으면_이상_없음과_근거를_준다():
    report = check_events(read_of([logon_fail(...)]))   # 기준 미만 실패 2건
    assert report.level == Level.OK
    assert report.total == 2 and report.period is not None

def test_판정은_UTC로_하고_표시는_한국_시각이다():
    # UTC 23:58~00:03 에 몰린 실패 → 경고 문구의 시각은 KST 08:58~09:03
```

- [ ] **Step 2–4:** 실패 확인 → 구현 → 통과
- [ ] **Step 5:** 커밋

### Task 7: `.evtx` 파일 읽기

**선행 조건:** 사용자가 개인 윈도우 PC에서 만든 `tests/data/sample_security.evtx` (테스트용 계정으로 로그인 실패 3회 이상, 이름·PC 이름 확인 후). 없으면 이 Task 는 멈추고 사용자에게 받는다.

**Files:**
- Modify: `seccheck/winevents.py`
- Create: `tests/test_evtx_read.py`, `tests/data/sample_security.evtx`, `tests/data/not_evtx.evtx`(아무 텍스트)

**Interfaces:**
- Produces:
  - `class EvtxUnreadable(Exception)` — 파일을 열 수 없거나 evtx 형식이 아님
  - `read_evtx(path: str, wanted_ids=WANTED_IDS, progress: Callable[[int], None] | None = None, cancelled: Callable[[], bool] | None = None) -> EvtxRead`
    - `WANTED_IDS = frozenset({4625, 1102, 4740, 4720, 4732})`, `total`은 전체 레코드 수, 원하는 ID만 `events`에 담음
    - 레코드 하나가 깨지면 `unreadable += 1` 하고 계속
    - `progress`는 1000 레코드마다 지금까지 읽은 수로 호출, `cancelled()`가 True 면 `OperationCancelled` 예외
  - `class OperationCancelled(Exception)`
  - 파일은 읽기 전용으로만 연다.

- [ ] **Step 1: 테스트** — 예시 파일에서 4625 가 1건 이상이고 channel 이 `Security`; `not_evtx.evtx` → `EvtxUnreadable`; 없는 경로 → `EvtxUnreadable`; 읽은 뒤 예시 파일의 수정 시각과 크기가 그대로
- [ ] **Step 2–4:** 실패 확인 → `Evtx.Evtx.Evtx(path)` 로 레코드 `.xml()`을 `parse_event_xml`에 넘겨 구현 → 통과
- [ ] **Step 5:** 커밋

### Task 8: 무결성 검사 감싸기

**Files:**
- Create: `seccheck/integrity_check.py`, `seccheck/paths.py`, `tests/test_integrity_check.py`

**Interfaces:**
- Consumes: `checker.ToolFiles`, `checker.make_snapshot`, `checker.run_verification`, `checker.log`
- Produces:
  - `paths.app_data_dir() -> Path` — 윈도우 `%LOCALAPPDATA%\SecurityCheck`, 그 외 `~/.security-check`; 환경 변수 `SECURITY_CHECK_HOME`이 있으면 그 경로 (테스트용)
  - `integrity_dir_for(folder: str) -> Path` — `app_data_dir()/"integrity"/sha256(정규화한 절대경로)[:16]`, 그 안에 `snapshot.json`, `integrity.key`, `integrity_log.txt`, `folder.txt`(원래 경로 기록)
  - `@dataclass(frozen=True) IntegrityReport(level: Level, findings: list[Finding], checked_count: int)`
  - `make_baseline(folder: str, replace: bool = False, key_file: str | None = None) -> IntegrityReport` (`key_file`이 없으면 기본 위치) — 이미 기준선이 있고 `replace=False`면 CHECK `"이미 기준선이 있습니다. 새로 만들면 이전 기준이 사라집니다."`(파일 건드리지 않음)
  - `verify(folder: str, key_file: str | None = None) -> IntegrityReport`
  - 기록 로그는 호출마다 그 폴더의 `integrity_log.txt`에 FileHandler 를 붙였다 떼는 방식 (`logging.basicConfig` 쓰지 않음)

- 판정: 변조·삭제·추가 → DANGER (`"바뀐 파일: a.txt"`, `"사라진 파일: …"`, `"새로 생긴 파일: …"`), 검사 실패 → CHECK `"확인하지 못한 파일: …"`, 스냅샷 거부·서명 불일치·키 없음 → CHECK (설명 문구), 기준선 없음 → CHECK `"이 폴더의 기준선이 없습니다. 먼저 기준선을 만들어 주세요."`, 그 외 OK. 파일 이름은 `checker.safe_path`로 표시.

- [ ] **Step 1: 테스트** (`monkeypatch.setenv("SECURITY_CHECK_HOME", tmp)`) — 기준선 후 그대로면 OK; 파일 수정 → DANGER 와 `"바뀐 파일: a.txt"`; 기준선 없이 verify → CHECK; 두 번째 `make_baseline` → CHECK 이고 snapshot.json 내용 그대로, `replace=True`면 새로 만듦; 검사 대상 폴더의 파일 목록이 작업 전후 같음; 두 폴더를 차례로 검사하면 각자의 `integrity_log.txt`에 각자 기록
- [ ] **Step 2–4:** 실패 확인 → 구현 → 통과
- [ ] **Step 5:** 커밋

### Task 9: 이 PC 점검 도우미

**Files:**
- Create: `seccheck/this_pc.py`, `tests/test_this_pc.py`

**Interfaces:**
- Produces:
  - `is_windows() -> bool`
  - `is_admin() -> bool` — 윈도우에서 `ctypes.windll.shell32.IsUserAnAdmin()`, 그 외 False
  - `export_security_log(dest: str) -> None` — `subprocess.run(["wevtutil", "epl", "Security", dest], check=True, capture_output=True, creationflags=CREATE_NO_WINDOW)`; 실패하면 `ExportFailed(메시지)`
  - `relaunch_as_admin() -> bool` — `ShellExecuteW(None, "runas", sys.executable, 인자, None, 1) > 32`
  - 앱은 임시 폴더(`tempfile.mkdtemp`)로 내보내고 분석 후 `finally`에서 지운다.

- [ ] **Step 1: 테스트** — 맥·리눅스에서 `is_admin() is False`; `export_security_log`가 만드는 명령 목록을 `monkeypatch`로 `subprocess.run`을 바꿔 확인; `wevtutil` 실패(`CalledProcessError`) → `ExportFailed`
- [ ] **Step 2–4:** 실패 확인 → 구현 → 통과
- [ ] **Step 5:** 커밋

### Task 10: 보고서 문장

**Files:**
- Create: `seccheck/report_text.py`, `tests/test_report_text.py`

**Interfaces:**
- Produces: `render_log_report(report: LogReport, source: str, made_at: datetime) -> str`, `render_integrity_report(report: IntegrityReport, folder: str, action: str, made_at: datetime) -> str`

```
=== 보안 점검 보고서 (로그 분석) ===
대상: C:\증거\security.evtx
작성 시각: 2026-11-13 14:30
판정: 위험 발견
분석한 기록: 12,345건 (2026-11-01 09:00 ~ 2026-11-13 14:00)

[위험] 로그인 반복 실패(급속): 10.0.0.5 — 10분 안에 45회 (…)
[확인] 계정이 잠겼습니다: admin
```

- [ ] **Step 1: 테스트** — 위 형식의 제목·판정·근거 줄, 항목 앞 `[위험]`·`[확인]`, 문제가 없으면 `이상 없음` 다음 줄에 근거
- [ ] **Step 2–4:** 실패 확인 → 구현 → 통과
- [ ] **Step 5:** 커밋

## 3부. 화면과 배포

### Task 11: 화면 — 로그 분석 탭

**Files:**
- Create: `seccheck/app.py`, `seccheck/__main__.py`, `seccheck/ui_common.py`

**Interfaces:**
- Consumes: Task 4–10 전부
- Produces: `python -m seccheck` 로 창이 열림. `ui_common.VerdictBanner`(판정 색 띠: DANGER `#C62828`, CHECK `#F9A825`, OK `#2E7D32`), `ui_common.FindingList`(ttk.Treeview, 열: 구분·내용), `ui_common.run_in_background(func, on_done, on_error, on_progress)` — 작업은 `threading.Thread`, 화면 갱신은 `after()`로만

- 화면 구성: [파일 열기…] [이 PC 점검] → 진행 표시줄 + [취소] → 판정 띠 → 근거 한 줄 → 항목 표 → [보고서 저장…]
- [이 PC 점검]: 윈도우가 아니면 비활성("윈도우에서만 쓸 수 있습니다"); 관리자가 아니면 "관리자 권한이 필요합니다" 안내와 [관리자 권한으로 다시 실행]
- 오류(`EvtxUnreadable`, `ExportFailed`, 예상 못 한 예외)는 대화 상자에 한국어 안내, 앱은 계속 동작

- [ ] **Step 1:** 구현 후 맥에서 `python -m seccheck`로 열어 `.evtx` 예시 파일 분석, 판정 띠·표·보고서 저장 확인 (화면 캡처 저장 `docs/screenshots/`)
- [ ] **Step 2:** 전체 테스트 통과 확인 후 커밋

### Task 12: 화면 — 파일 무결성 탭

**Files:**
- Modify: `seccheck/app.py`

- 화면 구성: [폴더 선택…] → 선택한 경로 표시 → [기준선 만들기] [검사하기] → 판정 띠·표·[보고서 저장…]
- 기준선이 이미 있으면 확인 창 "이미 기준선이 있습니다(만든 시각). 새로 만들면 이전 기준이 사라집니다. 계속할까요?" → 예일 때만 `replace=True`
- "고급 설정"(접힘): 비밀키 파일 위치 [찾기…] (USB 등). 지정하면 `key_file`로 넘기고, 비워 두면 기본 위치. 지정한 키가 없으면 기준선 만들 때 새로 만들고 그 위치를 알린다.

- [ ] **Step 1:** 구현 후 맥에서 확인: 기준선 → 그대로 검사(초록) → 파일 수정 후 검사(빨강) → 기준선 다시 만들기 확인 창
- [ ] **Step 2:** 커밋

### Task 13: 실행 파일 빌드와 문서

**Files:**
- Modify: `.github/workflows/ci.yml` (build 작업 추가)
- Create: `SecurityCheck.spec` 또는 빌드 명령, `docs/windows-checklist.md`, `README.md`

- 빌드: `windows-latest`, Python 3.12, `pyinstaller --onefile --windowed --name SecurityCheck --collect-data customtkinter seccheck/__main__.py`, 결과를 `actions/upload-artifact`로 올림 (이름 `SecurityCheck-windows`)
- `docs/windows-checklist.md`: 개인 윈도우 PC 점검표 — 첫 실행 경고 넘기기, 예시 `.evtx` 분석, 이 PC 점검(관리자/일반 계정 각각), 무결성 4단계, 고해상도 배율 125%·150%에서 글자 잘림 없음, 인터넷 끊고 실행
- README: 개요, 화면 캡처, 내려받기와 첫 실행 경고 안내, 두 도구와의 관계, 알려진 한계(서명 없음, 링크 접근 미탐지, 감사 정책 꺼짐), 테스트 수

- [ ] **Step 1:** push 후 Actions 에서 `SecurityCheck-windows` 산출물 생성 확인
- [ ] **Step 2:** 사용자가 개인 윈도우 PC에서 점검표 진행, 발견 사항 반영
- [ ] **Step 3:** 커밋, 태그 `v0.1.0`
