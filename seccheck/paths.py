"""앱이 쓰는 파일의 위치.

분석 대상 로그와 검사 대상 폴더에는 아무것도 쓰지 않는다. 앱이 만드는 파일은 모두 여기 아래에 둔다.
  윈도우: %LOCALAPPDATA%\\SecurityCheck
  그 외 : ~/.security-check   (개발용)
환경 변수 SECURITY_CHECK_HOME 이 있으면 그 경로를 쓴다 (테스트용).
"""

import os
import sys
from pathlib import Path


def app_data_dir() -> Path:
    override = os.environ.get("SECURITY_CHECK_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "SecurityCheck"
    return Path.home() / ".security-check"
