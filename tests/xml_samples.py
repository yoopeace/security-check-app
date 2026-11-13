"""테스트용 윈도우 이벤트 XML 만들기 도우미.

실제 .evtx 를 python-evtx 로 읽으면 레코드마다 이런 XML 이 나온다.
"""

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _system(event_id, time_created, channel):
    return (f'<System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
            f'<EventID Qualifiers="">{event_id}</EventID>'
            f'<TimeCreated SystemTime="{time_created}"/>'
            f'<Channel>{channel}</Channel><Computer>TEST-PC</Computer></System>')


def event_xml(event_id, time_created, data, channel="Security"):
    """EventData/Data[@Name] 형태의 이벤트 (4625, 4740, 4720, 4732 등)."""
    items = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return f'<Event xmlns="{NS}">{_system(event_id, time_created, channel)}<EventData>{items}</EventData></Event>'


def user_data_xml(event_id, time_created, element, data, channel="Security"):
    """UserData 아래에 이벤트별 요소가 있는 형태 (1102 보안 로그 삭제)."""
    items = "".join(f"<{k}>{v}</{k}>" for k, v in data.items())
    inner = f'<{element} xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">{items}</{element}>'
    return f'<Event xmlns="{NS}">{_system(event_id, time_created, channel)}<UserData>{inner}</UserData></Event>'
