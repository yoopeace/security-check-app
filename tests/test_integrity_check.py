"""파일 무결성 탭의 판정 (file-integrity-checker 를 감싼 것)"""

import os
import sys
from pathlib import Path

import pytest

# 윈도우는 chmod 로 파일 읽기를 막을 수 없다 (읽지 못하는 파일은 잠긴 파일·접근 권한으로 생기고, 같은 경로로 처리된다)
needs_chmod = pytest.mark.skipif(sys.platform == "win32", reason="윈도우에서는 chmod 로 읽기를 막을 수 없음")

from seccheck import integrity_check
from seccheck.integrity_check import integrity_dir_for, make_baseline, verify
from seccheck.paths import app_data_dir
from seccheck.verdict import Level


@pytest.fixture(autouse=True)
def app_home(tmp_path, monkeypatch):
    """앱 전용 폴더를 테스트용 임시 폴더로."""
    home = tmp_path / "app-home"
    monkeypatch.setenv("SECURITY_CHECK_HOME", str(home))
    return home


def make_folder(tmp_path, files, name="docs"):
    folder = tmp_path / name
    folder.mkdir()
    for rel, content in files.items():
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_text(content, encoding="utf-8")
    return folder


def listing(folder):
    return sorted(str(p.relative_to(folder)) for p in Path(folder).rglob("*"))


def messages(report, level=None):
    return [f.message for f in report.findings if level is None or f.level == level]


# ── 저장 위치 ──

def test_앱_전용_폴더는_환경_변수로_바꿀_수_있다(app_home):
    assert app_data_dir() == app_home


def test_폴더마다_저장_위치가_따로_정해진다(tmp_path, app_home):
    a, b = integrity_dir_for(str(tmp_path / "a")), integrity_dir_for(str(tmp_path / "b"))
    assert a != b
    assert a.parent == app_home / "integrity"
    assert integrity_dir_for(str(tmp_path / "a")) == a                       # 같은 폴더는 늘 같은 위치
    assert integrity_dir_for(str(tmp_path / "a" / ".." / "a")) == a          # 경로 표기가 달라도


# ── 기준선 만들기 ──

def test_기준선을_만들면_이상_없음과_파일_수(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본", "sub/b.txt": "원본"})
    report = make_baseline(str(folder))
    assert report.level == Level.OK
    assert report.checked_count == 2
    assert messages(report) == ["기준선을 만들었습니다: 파일 2개"]


def test_검사_대상_폴더에는_아무것도_쓰지_않는다(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    before = listing(folder)
    make_baseline(str(folder))
    verify(str(folder))
    assert listing(folder) == before
    assert (integrity_dir_for(str(folder)) / "snapshot.json").exists()


def test_이미_기준선이_있으면_덮어쓰지_않고_확인을_요청한다(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    make_baseline(str(folder))
    snapshot = integrity_dir_for(str(folder)) / "snapshot.json"
    original = snapshot.read_text(encoding="utf-8")
    (folder / "a.txt").write_text("변조", encoding="utf-8")

    report = make_baseline(str(folder))

    assert report.level == Level.CHECK
    assert messages(report) == ["이미 기준선이 있습니다. 새로 만들면 이전 기준이 사라집니다."]
    assert snapshot.read_text(encoding="utf-8") == original, "변조된 상태가 새 기준선으로 기록되면 안 된다"


def test_덮어쓰기를_확인하면_새_기준선을_만든다(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    make_baseline(str(folder))
    (folder / "a.txt").write_text("수정", encoding="utf-8")
    assert make_baseline(str(folder), replace=True).level == Level.OK
    assert verify(str(folder)).level == Level.OK


def test_없는_폴더로는_기준선을_만들_수_없다(tmp_path):
    report = make_baseline(str(tmp_path / "없음"))
    assert report.level == Level.CHECK
    assert messages(report) == [f"폴더를 찾을 수 없습니다: {tmp_path / '없음'}"]


@needs_chmod
def test_읽지_못한_파일이_있으면_기준선을_만들지_않는다(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본", "blocked.txt": "비밀"})
    (folder / "blocked.txt").chmod(0o000)
    try:
        report = make_baseline(str(folder))
    finally:
        (folder / "blocked.txt").chmod(0o644)
    assert report.level == Level.CHECK
    assert messages(report)[0] == "읽지 못한 파일이 있어 기준선을 만들지 않았습니다. 권한을 확인해 주세요."
    assert "확인하지 못한 파일: blocked.txt" in messages(report)[1]
    assert not (integrity_dir_for(str(folder)) / "snapshot.json").exists()


# ── 검사하기 ──

def test_바뀐_것이_없으면_이상_없음(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    make_baseline(str(folder))
    report = verify(str(folder))
    assert (report.level, report.checked_count) == (Level.OK, 1)
    assert messages(report) == ["기준선과 모두 같습니다: 파일 1개"]


def test_바뀐_파일_사라진_파일_새로_생긴_파일은_위험(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본", "b.txt": "원본"})
    make_baseline(str(folder))
    (folder / "a.txt").write_text("변조", encoding="utf-8")
    (folder / "b.txt").unlink()
    (folder / "c.txt").write_text("새 파일", encoding="utf-8")

    report = verify(str(folder))

    assert report.level == Level.DANGER
    assert messages(report, Level.DANGER) == ["바뀐 파일: a.txt", "사라진 파일: b.txt", "새로 생긴 파일: c.txt"]


@needs_chmod
def test_확인하지_못한_파일이_있으면_확인_필요(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본", "b.txt": "원본"})
    make_baseline(str(folder))
    (folder / "b.txt").chmod(0o000)
    try:
        report = verify(str(folder))
    finally:
        (folder / "b.txt").chmod(0o644)
    assert report.level == Level.CHECK
    assert messages(report)[0].startswith("확인하지 못한 파일: b.txt")


def test_기준선이_없는_폴더를_검사하면_확인_필요(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    report = verify(str(folder))
    assert report.level == Level.CHECK
    assert messages(report) == ["이 폴더의 기준선이 없습니다. 먼저 기준선을 만들어 주세요."]
    assert not integrity_dir_for(str(folder)).exists(), "기준선이 없을 때는 아무것도 만들지 않는다"


def test_기준선이_조작되면_확인_필요(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    make_baseline(str(folder))
    snapshot = integrity_dir_for(str(folder)) / "snapshot.json"
    snapshot.write_text(snapshot.read_text(encoding="utf-8").replace("a.txt", "z.txt"), encoding="utf-8")

    report = verify(str(folder))

    assert report.level == Level.CHECK
    assert messages(report) == ["기준선과 비밀키가 맞지 않습니다. 기준선이 조작되었거나 다른 비밀키를 지정했을 수 있습니다."]


def test_비밀키를_다른_곳에_둘_수_있다(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    usb = tmp_path / "usb"
    usb.mkdir()
    key = usb / "integrity.key"

    made = make_baseline(str(folder), key_file=str(key))

    assert key.exists()
    assert f"새 비밀키를 만들었습니다: {key}. 이 키가 있어야 검사할 수 있습니다." in messages(made)
    assert verify(str(folder), key_file=str(key)).level == Level.OK
    # 키를 지정하지 않으면 기본 위치의 키가 없으므로 검사할 수 없다
    assert messages(verify(str(folder))) == [f"비밀키가 없어 기준선을 확인할 수 없습니다: {integrity_dir_for(str(folder)) / 'integrity.key'}"]


# ── 검사 기록 ──

def test_여러_폴더를_차례로_검사해도_기록이_섞이지_않는다(tmp_path):
    a = make_folder(tmp_path, {"apple.txt": "1"}, name="a")
    b = make_folder(tmp_path, {"banana.txt": "2"}, name="b")
    make_baseline(str(a))
    make_baseline(str(b))
    verify(str(a))
    verify(str(b))
    log_a = (integrity_dir_for(str(a)) / "integrity_log.txt").read_text(encoding="utf-8")
    log_b = (integrity_dir_for(str(b)) / "integrity_log.txt").read_text(encoding="utf-8")
    assert "apple.txt" in log_a and "banana.txt" not in log_a
    assert "banana.txt" in log_b and "apple.txt" not in log_b


def test_원래_폴더_경로를_기록해_둔다(tmp_path):
    folder = make_folder(tmp_path, {"a.txt": "원본"})
    make_baseline(str(folder))
    recorded = (integrity_dir_for(str(folder)) / "folder.txt").read_text(encoding="utf-8")
    assert recorded == os.path.abspath(str(folder))
