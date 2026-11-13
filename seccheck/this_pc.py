"""이 PC 점검: 지금 쓰는 윈도우 PC 의 보안 로그를 분석하기 위한 도우미.

보안 로그는 관리자 권한이 있어야 읽을 수 있다. 권한이 있으면 윈도우 기본 명령
`wevtutil epl Security <파일>` 로 임시 .evtx 파일을 만들고, 파일 열기와 같은 경로로 분석한다.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager

# 명령을 실행할 때 검은 콘솔 창이 깜빡이지 않게 (윈도우에서만 있는 값)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class ExportFailed(Exception):
    """보안 로그를 내보내지 못했다. 메시지는 화면에 그대로 보여 준다."""


def is_windows() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _decode(raw) -> str:
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    # 한국어 윈도우의 명령 출력은 cp949(OEM 코드 페이지)
    for encoding in ("cp949", "utf-8"):
        try:
            return raw.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").strip()


def export_security_log(dest: str) -> None:
    try:
        subprocess.run(["wevtutil", "epl", "Security", dest],
                       check=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
    except FileNotFoundError as e:
        raise ExportFailed("이 PC 점검은 윈도우에서만 쓸 수 있습니다.") from e
    except subprocess.CalledProcessError as e:
        detail = _decode(e.stderr) or _decode(e.stdout) or f"오류 코드 {e.returncode}"
        raise ExportFailed(f"보안 로그를 내보내지 못했습니다: {detail}") from e


@contextmanager
def exported_security_log():
    """보안 로그를 임시 .evtx 로 내보내 그 경로를 주고, 끝나면 임시 폴더째 지운다."""
    folder = tempfile.mkdtemp(prefix="SecurityCheck-")
    try:
        path = os.path.join(folder, "Security.evtx")
        export_security_log(path)
        yield path
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def relaunch_as_admin() -> bool:
    """관리자 권한으로 앱을 다시 띄운다 (윈도우 권한 확인 창). 띄웠으면 True."""
    if not is_windows():
        return False
    import ctypes
    if getattr(sys, "frozen", False):        # 실행 파일(SecurityCheck.exe)로 실행 중
        params = subprocess.list2cmdline(sys.argv[1:])
    else:                                    # 개발 중: python -m seccheck
        params = subprocess.list2cmdline(["-m", "seccheck", *sys.argv[1:]])
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    return result > 32
