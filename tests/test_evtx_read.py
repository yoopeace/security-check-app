""".evtx 파일 읽기 (tests/data 의 공개 예시 파일 사용)"""

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from seccheck.log_check import check_events
from seccheck.verdict import Level
from seccheck.winevents import EvtxUnreadable, OperationCancelled, read_evtx

DATA = Path(__file__).parent / "data"
SECURITY = str(DATA / "security.evtx")


def _file_state(path):
    return (os.stat(path).st_mtime_ns, os.stat(path).st_size, hashlib.sha256(Path(path).read_bytes()).hexdigest())


@pytest.fixture(scope="module")
def security():
    """security.evtx 를 한 번만 읽어 여러 테스트가 함께 쓴다 (한 번에 몇 초 걸림)."""
    progress_calls = []
    before = _file_state(SECURITY)
    read = read_evtx(SECURITY, progress=progress_calls.append)
    return {"read": read, "progress": progress_calls, "before": before, "after": _file_state(SECURITY)}


def test_보안_로그에서_판정에_쓰는_이벤트만_골라_읽는다(security):
    read = security["read"]
    assert read.total == 2261
    assert read.unreadable == 0
    assert read.channels == frozenset({"Security"})
    assert read.logon_records == 583          # 4624 583건 + 4625 0건
    ids = sorted({e.event_id for e in read.events})
    assert ids == [4720, 4732]
    assert sum(e.event_id == 4720 for e in read.events) == 2


def test_파일_전체_기록의_기간을_알려준다(security):
    start, end = security["read"].period_utc
    assert start == datetime(2016, 7, 8, 18, 12, 51, 681641, tzinfo=timezone.utc)
    assert end == datetime(2017, 4, 14, 1, 21, 10, 906950, tzinfo=timezone.utc)


def test_실제_보안_로그를_판정까지_이어서_할_수_있다(security):
    report = check_events(security["read"])
    assert report.level == Level.CHECK
    assert any(f.message.startswith("새 계정이 만들어졌습니다:") for f in report.findings)


def test_보안_로그가_아닌_파일은_채널로_알_수_있다():
    read = read_evtx(str(DATA / "system.evtx"))
    assert read.channels == frozenset({"System"})
    assert (read.events, read.logon_records) == ([], 0)


def test_깨진_기록은_세고_나머지는_계속_읽는다():
    read = read_evtx(str(DATA / "dns_log_malformed.evtx"))
    assert (read.total, read.unreadable) == (5, 4)


@pytest.mark.parametrize("path", [
    str(DATA / "not_evtx.evtx"),     # 확장자만 .evtx
    str(DATA / "없는파일.evtx"),
    str(DATA),                       # 폴더
])
def test_evtx_가_아니거나_열_수_없으면_EvtxUnreadable(path):
    with pytest.raises(EvtxUnreadable):
        read_evtx(path)


def test_빈_파일도_EvtxUnreadable(tmp_path):
    empty = tmp_path / "empty.evtx"
    empty.write_bytes(b"")
    with pytest.raises(EvtxUnreadable):
        read_evtx(str(empty))


def test_분석한_파일은_전혀_바뀌지_않는다(security):
    # 증거 파일이므로 내용·크기·수정 시각 어느 것도 바뀌면 안 된다
    assert security["before"] == security["after"]


def test_진행_상황을_1000건마다_알려준다(security):
    assert security["progress"] == [1000, 2000]


def test_취소하면_OperationCancelled():
    with pytest.raises(OperationCancelled):
        read_evtx(SECURITY, cancelled=lambda: True)
