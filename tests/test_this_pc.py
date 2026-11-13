"""이 PC 점검 도우미 (관리자 권한 확인, 보안 로그 내보내기)"""

import os
import subprocess
import sys

import pytest

from seccheck import this_pc
from seccheck.this_pc import ExportFailed, export_security_log, exported_security_log, is_admin, is_windows


def test_윈도우인지_알려준다():
    assert is_windows() == (sys.platform == "win32")


@pytest.mark.skipif(sys.platform == "win32", reason="윈도우가 아닐 때의 동작")
def test_윈도우가_아니면_관리자가_아닌_것으로_본다():
    assert is_admin() is False
    assert this_pc.relaunch_as_admin() is False


def test_보안_로그를_윈도우_기본_명령으로_내보낸다(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(this_pc.subprocess, "run", lambda args, **kw: calls.append((args, kw)))
    dest = str(tmp_path / "security.evtx")

    export_security_log(dest)

    args, kw = calls[0]
    assert args == ["wevtutil", "epl", "Security", dest]
    assert kw["check"] is True and kw["capture_output"] is True


def test_내보내기가_실패하면_ExportFailed와_윈도우의_설명(monkeypatch, tmp_path):
    def refuse(args, **kw):
        raise subprocess.CalledProcessError(5, args, stderr="액세스가 거부되었습니다.".encode("cp949"))
    monkeypatch.setattr(this_pc.subprocess, "run", refuse)

    with pytest.raises(ExportFailed, match="액세스가 거부되었습니다"):
        export_security_log(str(tmp_path / "s.evtx"))


def test_wevtutil_이_없으면_ExportFailed(monkeypatch, tmp_path):
    def missing(args, **kw):
        raise FileNotFoundError("wevtutil")
    monkeypatch.setattr(this_pc.subprocess, "run", missing)

    with pytest.raises(ExportFailed, match="윈도우에서만"):
        export_security_log(str(tmp_path / "s.evtx"))


def test_임시로_내보낸_파일은_분석_뒤_지운다(monkeypatch):
    def fake_export(args, **kw):
        open(args[3], "wb").write(b"evtx")
    monkeypatch.setattr(this_pc.subprocess, "run", fake_export)

    with exported_security_log() as path:
        assert os.path.exists(path)
        folder = os.path.dirname(path)
    assert not os.path.exists(folder)


def test_내보내기_중_실패해도_임시_폴더를_지운다(monkeypatch):
    made = []
    real_mkdtemp = this_pc.tempfile.mkdtemp
    monkeypatch.setattr(this_pc.tempfile, "mkdtemp", lambda **kw: made.append(real_mkdtemp(**kw)) or made[-1])
    monkeypatch.setattr(this_pc.subprocess, "run", lambda args, **kw: (_ for _ in ()).throw(FileNotFoundError()))

    with pytest.raises(ExportFailed):
        with exported_security_log():
            pass
    assert made and not os.path.exists(made[0])
