"""윈도우 보안 로그 판정 규칙 (설계 7-3절).

| 이벤트 | 뜻                         | 판정      |
|--------|----------------------------|-----------|
| 4625   | 로그인 실패                | 브루트포스 기준을 넘으면 위험 |
| 1102   | 보안 로그 삭제             | 위험      |
| 4740   | 계정 잠금                  | 확인 필요 |
| 4720   | 새 계정 생성               | 확인 필요 |
| 4732   | 관리자 그룹에 계정 추가    | 확인 필요 |

판정은 UTC 로 하고, 화면에 보이는 시각은 한국 시각(KST)이다.
근거가 없거나(보안 로그가 아님, 로그인 기록 없음) 일부를 읽지 못했으면 '이상 없음'이 아니라 '확인 필요'다.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from log_analyzer import DEFAULT_TIERS, judge_failures

from seccheck.verdict import Finding, Level, overall
from seccheck.winevents import EvtxRead

KST = timezone(timedelta(hours=9))

LOGON_FAILED = 4625
LOG_CLEARED = 1102
ACCOUNT_LOCKED = 4740
ACCOUNT_CREATED = 4720
ADDED_TO_LOCAL_GROUP = 4732
ADMINISTRATORS_SID = "S-1-5-32-544"

# IpAddress 가 이 값들이면 원격이 아니라 이 PC 앞(또는 PC 자신)에서 시도한 것이다
LOCAL_ADDRESSES = {"", "-", "127.0.0.1", "::1"}
EMPTY_NAMES = {"", "-"}


@dataclass(frozen=True)
class LogReport:
    level: Level
    findings: list            # Finding, 위험 → 확인 필요 순
    total: int                # 분석한 전체 기록 수
    period: tuple | None      # 분석한 기록의 (처음, 끝) 한국 시각


def failure_key(data: dict) -> str:
    """로그인 실패를 묶는 기준: 원격 IP 가 있으면 IP, 없으면 계정."""
    ip = (data.get("IpAddress") or "").strip()
    if ip not in LOCAL_ADDRESSES:
        return ip
    user = (data.get("TargetUserName") or "").strip()
    return f"계정 {user}" if user not in EMPTY_NAMES else "계정 (알 수 없음)"


def _kst(moment: datetime) -> datetime:
    return moment.astimezone(KST)


def _when(moment: datetime) -> str:
    return f"{_kst(moment):%Y-%m-%d %H:%M}"


def _window_text(minutes: int) -> str:
    return f"{minutes // 60}시간" if minutes % 60 == 0 else f"{minutes}분"


def _range_text(start: datetime, end: datetime) -> str:
    start, end = _kst(start), _kst(end)
    end_text = f"{end:%H:%M}" if start.date() == end.date() else f"{end:%Y-%m-%d %H:%M}"
    return f"{start:%Y-%m-%d %H:%M} ~ {end_text}"


def _name(value: str | None, fallback: str | None = None) -> str:
    value = (value or "").strip()
    if value not in EMPTY_NAMES:
        return value
    fallback = (fallback or "").strip()
    return fallback if fallback not in EMPTY_NAMES else "(알 수 없음)"


def _member(data: dict, names_by_sid: dict) -> str:
    """4732 의 추가된 구성원: 이름이 있으면 이름, SID 뿐이면 '이름 (SID)' 또는 SID."""
    name = (data.get("MemberName") or "").strip()
    if name not in EMPTY_NAMES:
        return name
    sid = (data.get("MemberSid") or "").strip()
    if sid in EMPTY_NAMES:
        return "(알 수 없음)"
    known = (names_by_sid.get(sid) or "").strip()
    return f"{known} ({sid})" if known not in EMPTY_NAMES else sid


def check_events(read: EvtxRead, tiers=DEFAULT_TIERS) -> LogReport:
    findings = []

    failures = [(e.time_utc, failure_key(e.data)) for e in read.events if e.event_id == LOGON_FAILED]
    for alert in judge_failures(failures, tiers):
        findings.append(Finding(Level.DANGER,
                                f"로그인 반복 실패({alert.tier}): {alert.ip} — "
                                f"{_window_text(alert.window_minutes)} 안에 {alert.count}회 "
                                f"({_range_text(alert.start, alert.end)})"))

    # 구성원이 SID 로만 남은 경우 사람이 읽을 수 있게, 같은 로그의 계정 생성 기록에서 이름을 찾는다
    names_by_sid = {e.data.get("TargetSid"): e.data.get("TargetUserName")
                    for e in read.events if e.event_id == ACCOUNT_CREATED and e.data.get("TargetSid")}

    for e in sorted(read.events, key=lambda e: e.time_utc):
        if e.event_id == LOG_CLEARED:
            findings.append(Finding(Level.DANGER, f"보안 로그가 삭제되었습니다: {_when(e.time_utc)} "
                                                  f"(삭제한 계정: {_name(e.data.get('SubjectUserName'))})"))
        elif e.event_id == ACCOUNT_LOCKED:
            findings.append(Finding(Level.CHECK, f"계정이 잠겼습니다: {_name(e.data.get('TargetUserName'))} "
                                                 f"({_when(e.time_utc)})"))
        elif e.event_id == ACCOUNT_CREATED:
            findings.append(Finding(Level.CHECK, f"새 계정이 만들어졌습니다: {_name(e.data.get('TargetUserName'))} "
                                                 f"({_when(e.time_utc)})"))
        elif e.event_id == ADDED_TO_LOCAL_GROUP and e.data.get("TargetSid") == ADMINISTRATORS_SID:
            member = _member(e.data, names_by_sid)
            findings.append(Finding(Level.CHECK, f"관리자 그룹에 계정이 추가되었습니다: {member} "
                                                 f"({_when(e.time_utc)})"))

    # 근거가 없거나 일부를 읽지 못했으면 '이상 없음'이라고 할 수 없다
    if "Security" not in read.channels:
        findings.append(Finding(Level.CHECK, "보안 로그가 아닙니다. 이벤트 뷰어의 '보안' 로그를 저장한 파일인지 확인해 주세요."))
    elif read.logon_records == 0:
        findings.append(Finding(Level.CHECK, "분석할 로그인 기록이 없습니다. 감사 정책이 꺼져 있을 수 있습니다."))
    if read.unreadable:
        findings.append(Finding(Level.CHECK, f"읽지 못한 기록이 {read.unreadable}건 있습니다."))

    findings.sort(key=lambda f: -f.level)   # 위험 → 확인 필요 (같은 단계 안에서는 순서 유지)
    period = tuple(_kst(t) for t in read.period_utc) if read.period_utc else None
    return LogReport(overall(findings), findings, read.total, period)
