"""윈도우 보안 로그 판정 규칙 (설계 7-3절)"""

from datetime import datetime, timedelta, timezone

import pytest

from seccheck.log_check import KST, check_events, failure_key
from seccheck.verdict import Finding, Level
from seccheck.winevents import EvtxRead, WinEvent

UTC = timezone.utc


def utc(text):
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def ev(event_id, when, **data):
    return WinEvent(event_id, utc(when), "Security", data)


def logon_fail(when, ip="10.0.0.5", user="admin"):
    return ev(4625, when, IpAddress=ip, TargetUserName=user)


def burst(count, start="2026-11-13 01:02:00", ip="10.0.0.5", user="admin", every_seconds=4):
    base = utc(start)
    return [WinEvent(4625, base + timedelta(seconds=i * every_seconds), "Security",
                     {"IpAddress": ip, "TargetUserName": user}) for i in range(count)]


def read_of(events, total=None, unreadable=0, channels=frozenset({"Security"}), logon_records=None):
    times = [e.time_utc for e in events]
    return EvtxRead(
        events=events,
        total=len(events) if total is None else total,
        unreadable=unreadable,
        channels=channels,
        logon_records=sum(e.event_id == 4625 for e in events) + 10 if logon_records is None else logon_records,
        period_utc=(min(times), max(times)) if times else None,
    )


def messages(report, level=None):
    return [f.message for f in report.findings if level is None or f.level == level]


# ── 로그인 실패를 묶는 기준 ──

def test_원격_IP가_있으면_IP별로_센다():
    assert failure_key({"IpAddress": "10.0.0.5", "TargetUserName": "admin"}) == "10.0.0.5"


@pytest.mark.parametrize("ip", ["-", "", "127.0.0.1", "::1"])
def test_이_PC_자신에서_온_실패는_계정별로_센다(ip):
    assert failure_key({"IpAddress": ip, "TargetUserName": "admin"}) == "계정 admin"


@pytest.mark.parametrize("user", ["-", ""])
def test_IP도_계정도_없으면_알_수_없음으로_묶는다(user):
    assert failure_key({"IpAddress": "-", "TargetUserName": user}) == "계정 (알 수 없음)"
    assert failure_key({}) == "계정 (알 수 없음)"


# ── 위험 ──

def test_짧은_시간에_몰린_로그인_실패는_위험():
    report = check_events(read_of(burst(45)))
    assert report.level == Level.DANGER
    # 판정은 UTC, 표시는 한국 시각 (UTC 01:02 → KST 10:02)
    assert messages(report, Level.DANGER) == ["로그인 반복 실패(급속): 10.0.0.5 — 10분 안에 45회 (2026-11-13 10:02 ~ 10:04)"]


def test_PC_앞에서_반복된_실패는_계정으로_표시된다():
    report = check_events(read_of(burst(8, ip="-", user="kim", every_seconds=600)))
    assert messages(report, Level.DANGER) == [
        "로그인 반복 실패(누적): 계정 kim — 24시간 안에 8회 (2026-11-13 10:02 ~ 11:12)"]


def test_보안_로그_삭제는_위험():
    report = check_events(read_of([ev(1102, "2026-11-13 02:00:00", SubjectUserName="kim")]))
    assert report.level == Level.DANGER
    assert messages(report) == ["보안 로그가 삭제되었습니다: 2026-11-13 11:00 (삭제한 계정: kim)"]


# ── 확인 필요 ──

def test_계정_잠금은_확인_필요():
    report = check_events(read_of([ev(4740, "2026-11-13 03:00:00", TargetUserName="admin")]))
    assert (report.level, messages(report)) == (Level.CHECK, ["계정이 잠겼습니다: admin (2026-11-13 12:00)"])


def test_새_계정_생성은_확인_필요():
    report = check_events(read_of([ev(4720, "2026-11-13 03:00:00", TargetUserName="guest2")]))
    assert messages(report) == ["새 계정이 만들어졌습니다: guest2 (2026-11-13 12:00)"]


def test_관리자_그룹에_추가되면_확인_필요():
    added = ev(4732, "2026-11-13 03:00:00", TargetSid="S-1-5-32-544", MemberName="-", MemberSid="S-1-5-21-1-2-3-1001")
    report = check_events(read_of([added]))
    assert messages(report) == ["관리자 그룹에 계정이 추가되었습니다: S-1-5-21-1-2-3-1001 (2026-11-13 12:00)"]


def test_관리자가_아닌_그룹에_추가된_것은_무시한다():
    added = ev(4732, "2026-11-13 03:00:00", TargetSid="S-1-5-32-555", MemberName="CN=kim")
    assert check_events(read_of([added])).level == Level.OK


def test_보안_로그가_아니면_확인_필요():
    report = check_events(read_of([], total=500, channels=frozenset({"System"}), logon_records=0))
    assert report.level == Level.CHECK
    assert messages(report) == ["보안 로그가 아닙니다. 이벤트 뷰어의 '보안' 로그를 저장한 파일인지 확인해 주세요."]


def test_로그인_기록이_하나도_없으면_확인_필요():
    report = check_events(read_of([], total=300, logon_records=0))
    assert messages(report) == ["분석할 로그인 기록이 없습니다. 감사 정책이 꺼져 있을 수 있습니다."]


def test_읽지_못한_기록이_있으면_확인_필요():
    report = check_events(read_of(burst(2), unreadable=3))
    assert (report.level, messages(report)) == (Level.CHECK, ["읽지 못한 기록이 3건 있습니다."])


# ── 이상 없음과 근거 ──

def test_문제가_없으면_이상_없음과_근거를_준다():
    report = check_events(read_of(burst(2), total=1234))
    assert report.level == Level.OK
    assert report.findings == []
    assert report.total == 1234
    start, end = report.period
    assert start.tzinfo == KST and start.hour == 10


def test_위험이_확인_필요보다_먼저_나온다():
    events = [ev(4740, "2026-11-13 00:00:00", TargetUserName="admin"),
              ev(1102, "2026-11-13 05:00:00", SubjectUserName="kim")]
    levels = [f.level for f in check_events(read_of(events)).findings]
    assert levels == [Level.DANGER, Level.CHECK]
