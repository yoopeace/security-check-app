"""윈도우 이벤트 XML 해석"""

from datetime import datetime, timezone

import pytest

from seccheck.winevents import EventParseError, WinEvent, parse_event_xml
from tests.xml_samples import event_xml, user_data_xml


def test_로그인_실패_이벤트를_읽는다():
    e = parse_event_xml(event_xml(4625, "2026-11-13T01:02:03.1234567Z",
                                  {"TargetUserName": "admin", "IpAddress": "10.0.0.5", "LogonType": "3"}))
    assert e.event_id == 4625
    assert e.time_utc == datetime(2026, 11, 13, 1, 2, 3, 123456, tzinfo=timezone.utc)
    assert e.channel == "Security"
    assert e.data["IpAddress"] == "10.0.0.5"
    assert e.data["TargetUserName"] == "admin"


def test_python_evtx_가_내는_시각_형식도_UTC로_읽는다():
    # python-evtx 는 시간대 표시 없이 'YYYY-MM-DD HH:MM:SS.ffffff' 로 낸다 (값은 UTC)
    e = parse_event_xml(event_xml(4625, "2026-11-13 01:02:03.123456", {}))
    assert e.time_utc == datetime(2026, 11, 13, 1, 2, 3, 123456, tzinfo=timezone.utc)


def test_소수점_없는_시각도_읽는다():
    e = parse_event_xml(event_xml(4740, "2026-11-13 01:02:03", {"TargetUserName": "admin"}))
    assert e.time_utc == datetime(2026, 11, 13, 1, 2, 3, tzinfo=timezone.utc)


def test_값이_빈_항목은_빈_문자열로_담는다():
    e = parse_event_xml(event_xml(4625, "2026-11-13T01:02:03Z", {"IpAddress": ""}))
    assert e.data["IpAddress"] == ""


def test_로그_삭제_이벤트는_UserData에서_읽는다():
    e = parse_event_xml(user_data_xml(1102, "2026-11-13T02:00:00Z", "LogFileCleared",
                                      {"SubjectUserName": "kim", "SubjectDomainName": "TEST-PC"}))
    assert e.event_id == 1102
    assert e.data["SubjectUserName"] == "kim"


def test_보안_로그가_아닌_채널도_그대로_담는다():
    e = parse_event_xml(event_xml(7036, "2026-11-13T02:00:00Z", {}, channel="System"))
    assert e.channel == "System"


@pytest.mark.parametrize("broken", [
    "<Event><System>",                                                        # XML 이 깨짐
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"/>',  # System 없음
    event_xml("abc", "2026-11-13T01:02:03Z", {}),                             # 이벤트 ID 가 숫자가 아님
    event_xml(4625, "어제", {}),                                               # 시각을 읽을 수 없음
])
def test_읽을_수_없는_이벤트는_EventParseError(broken):
    with pytest.raises(EventParseError):
        parse_event_xml(broken)


def test_WinEvent_는_값으로_비교할_수_있다():
    a = parse_event_xml(event_xml(4740, "2026-11-13T01:02:03Z", {"TargetUserName": "admin"}))
    assert a == WinEvent(4740, datetime(2026, 11, 13, 1, 2, 3, tzinfo=timezone.utc), "Security",
                         {"TargetUserName": "admin"})
