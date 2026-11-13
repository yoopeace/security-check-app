"""윈도우 이벤트 로그 해석.

이벤트 하나는 XML 로 표현된다 (python-evtx 가 .evtx 레코드마다 이 XML 을 만든다).
여기서는 판정에 필요한 것만 꺼내 WinEvent 값으로 바꾼다.
  - System/EventID, System/TimeCreated@SystemTime, System/Channel
  - EventData/Data[@Name] 들 (대부분의 보안 이벤트)
  - UserData 아래 첫 요소의 자식들 (1102 보안 로그 삭제 등)
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class EventParseError(ValueError):
    """이벤트 XML 이 깨졌거나 필수 항목(이벤트 ID, 시각)이 없다."""


@dataclass(frozen=True)
class WinEvent:
    event_id: int
    time_utc: datetime        # UTC 시간대 정보 포함
    channel: str              # 'Security' 면 보안 로그
    data: dict                # 항목 이름 → 값 (값이 없으면 빈 문자열)


@dataclass(frozen=True)
class EvtxRead:
    """.evtx 파일 하나를 읽은 결과."""
    events: list              # 판정에 쓰는 이벤트만 (WinEvent)
    total: int                # 파일 안의 전체 기록 수
    unreadable: int           # 읽지 못한 기록 수
    channels: frozenset       # 파일에 들어 있던 채널 이름들
    logon_records: int = 0    # 로그인 성공·실패 기록(4624·4625) 수. 0 이면 감사 정책이 꺼져 있을 수 있다
    period_utc: tuple | None = None   # 파일 전체 기록의 (처음, 끝) 시각


def _local_name(tag: str) -> str:
    """'{네임스페이스}이름' 에서 이름만."""
    return tag.rsplit("}", 1)[-1]


def parse_time(text: str) -> datetime:
    """이벤트 시각을 UTC 로 읽는다.

    wevtutil 은 '2026-11-13T01:02:03.1234567Z', python-evtx 는 '2026-11-13 01:02:03.123456'
    (시간대 표시 없음, 값은 UTC) 형식으로 낸다. 시간대가 없으면 UTC 로 본다.
    """
    try:
        value = datetime.fromisoformat(text)
    except (TypeError, ValueError) as e:
        raise EventParseError(f"시각을 읽을 수 없습니다: {text!r}") from e
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_event_xml(xml: str) -> WinEvent:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise EventParseError(f"XML 을 읽을 수 없습니다: {e}") from e

    system = root.find(f"{NS}System")
    if system is None:
        raise EventParseError("System 항목이 없습니다")
    event_id_node = system.find(f"{NS}EventID")
    time_node = system.find(f"{NS}TimeCreated")
    if event_id_node is None or time_node is None:
        raise EventParseError("이벤트 ID 나 시각이 없습니다")
    try:
        event_id = int((event_id_node.text or "").strip())
    except ValueError as e:
        raise EventParseError(f"이벤트 ID 가 숫자가 아닙니다: {event_id_node.text!r}") from e
    time_utc = parse_time(time_node.get("SystemTime"))
    channel = (system.findtext(f"{NS}Channel") or "").strip()

    data = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for item in event_data.findall(f"{NS}Data"):
            name = item.get("Name")
            if name:
                data[name] = item.text or ""
    user_data = root.find(f"{NS}UserData")
    if user_data is not None and len(user_data):
        for item in user_data[0]:
            data[_local_name(item.tag)] = item.text or ""

    return WinEvent(event_id, time_utc, channel, data)
