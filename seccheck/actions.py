"""화면 버튼이 부르는 동작. 화면은 이 함수들의 결과(값)를 그리기만 한다.

예상할 수 있는 실패(evtx 가 아닌 파일, 보안 로그 내보내기 실패)는 앱을 멈추지 않고
'확인 필요' 판정과 이유 한 줄로 바꿔 돌려준다. 취소(OperationCancelled)만 그대로 올려보낸다.
"""

from datetime import datetime
from pathlib import Path

from seccheck.integrity_check import SNAPSHOT_NAME, integrity_dir_for
from seccheck.log_check import LogReport, check_events
from seccheck.this_pc import ExportFailed, exported_security_log
from seccheck.verdict import Finding, Level
from seccheck.winevents import EvtxUnreadable, read_evtx

UNREADABLE_FILE = "읽을 수 없는 파일입니다. 이벤트 뷰어에서 '다른 이름으로 저장'한 .evtx 파일인지 확인해 주세요."


def _check_only(message: str) -> LogReport:
    return LogReport(Level.CHECK, [Finding(Level.CHECK, message)], 0, None)


def analyze_file(path: str, progress=None, cancelled=None) -> LogReport:
    try:
        read = read_evtx(path, progress=progress, cancelled=cancelled)
    except EvtxUnreadable:
        return _check_only(UNREADABLE_FILE)
    return check_events(read)


def analyze_this_pc(progress=None, cancelled=None) -> LogReport:
    try:
        with exported_security_log() as path:
            return analyze_file(path, progress, cancelled)
    except ExportFailed as e:
        return _check_only(str(e))


def baseline_time(folder: str) -> datetime | None:
    """이 폴더의 기준선을 만든(마지막으로 저장한) 시각. 기준선이 없으면 None."""
    snapshot = integrity_dir_for(folder) / SNAPSHOT_NAME
    if not snapshot.exists():
        return None
    return datetime.fromtimestamp(Path(snapshot).stat().st_mtime)
