"""화면 버튼이 부르는 동작 (화면 없이 값으로 확인)"""

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pytest

from seccheck import actions
from seccheck.actions import analyze_file, analyze_this_pc, baseline_time
from seccheck.integrity_check import make_baseline
from seccheck.this_pc import ExportFailed
from seccheck.verdict import Level
from seccheck.winevents import OperationCancelled

DATA = Path(__file__).parent / "data"


def test_evtx_파일을_분석해_판정까지_돌려준다():
    report = analyze_file(str(DATA / "security.evtx"))
    assert report.level == Level.CHECK
    assert report.total == 2261


def test_evtx_가_아니면_꺼지지_않고_확인_필요():
    report = analyze_file(str(DATA / "not_evtx.evtx"))
    assert report.level == Level.CHECK
    assert [f.message for f in report.findings] == [
        "읽을 수 없는 파일입니다. 이벤트 뷰어에서 '다른 이름으로 저장'한 .evtx 파일인지 확인해 주세요."]


def test_취소는_그대로_알린다():
    with pytest.raises(OperationCancelled):
        analyze_file(str(DATA / "security.evtx"), cancelled=lambda: True)


def test_이_PC_점검은_내보낸_보안_로그를_같은_방식으로_분석한다(monkeypatch):
    @contextmanager
    def fake_export():
        yield str(DATA / "security.evtx")
    monkeypatch.setattr(actions, "exported_security_log", fake_export)

    assert analyze_this_pc().total == 2261


def test_보안_로그를_내보내지_못하면_그_이유를_확인_필요로(monkeypatch):
    @contextmanager
    def refuse():
        raise ExportFailed("보안 로그를 내보내지 못했습니다: 액세스가 거부되었습니다.")
        yield
    monkeypatch.setattr(actions, "exported_security_log", refuse)

    report = analyze_this_pc()

    assert report.level == Level.CHECK
    assert [f.message for f in report.findings] == ["보안 로그를 내보내지 못했습니다: 액세스가 거부되었습니다."]


def test_기준선을_만든_시각을_알려준다(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_CHECK_HOME", str(tmp_path / "home"))
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("원본", encoding="utf-8")

    assert baseline_time(str(folder)) is None
    make_baseline(str(folder))
    made = baseline_time(str(folder))
    assert isinstance(made, datetime)
    assert abs((datetime.now() - made).total_seconds()) < 60
