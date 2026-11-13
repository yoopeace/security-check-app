"""화면 스모크 테스트. 화면을 띄울 수 없는 환경(우분투 CI 등)에서는 건너뛴다.

화면 모양과 사용 흐름은 docs/windows-checklist.md 점검표로 사람이 확인한다.
"""

import time

import pytest

tkinter = pytest.importorskip("tkinter")


def _keep_alive_root():
    """테스트가 끝날 때까지 살려 두는 숨은 기본 창 (화면을 띄울 수 없으면 None).

    맥의 Tk 9.x 는 마지막 Tk 창을 닫은 뒤 새 Tk 창을 만들면 비정상 종료된다.
    기본 창 하나를 계속 살려 두면 그 사이에 다른 창을 만들고 닫아도 괜찮다.
    (실제 앱은 창을 한 번만 만들므로 해당 없음)
    """
    try:
        root = tkinter.Tk()
    except tkinter.TclError:
        return None
    root.withdraw()
    return root


ROOT = _keep_alive_root()
pytestmark = pytest.mark.skipif(ROOT is None, reason="화면을 띄울 수 없는 환경")

from seccheck.app import App                     # noqa: E402
from seccheck.ui_common import BackgroundTask, ConfirmDialog    # noqa: E402
from seccheck.winevents import OperationCancelled  # noqa: E402


def pump(root, until, timeout=5.0):
    deadline = time.time() + timeout
    while not until() and time.time() < deadline:
        root.update()
        time.sleep(0.01)


def test_앱_창이_열리고_두_탭이_있다():
    app = App()
    try:
        app.update()
        assert app.title() == "보안 점검 도구"
        assert app.tab_names == ("로그 분석", "파일 무결성")
    finally:
        app.destroy()


def test_백그라운드_작업의_진행과_결과가_화면_쪽으로_전달된다():
    root = tkinter.Toplevel(ROOT)
    progress, done = [], []

    def work(progress, cancelled):
        progress(1000)
        return 42

    BackgroundTask(root, work, on_done=done.append, on_error=pytest.fail, on_progress=progress.append)
    pump(root, lambda: done)
    root.destroy()
    assert (progress, done) == ([1000], [42])


def test_작업_중_오류도_화면_쪽으로_전달된다():
    root = tkinter.Toplevel(ROOT)
    errors = []

    def work(progress, cancelled):
        raise ValueError("깨짐")

    BackgroundTask(root, work, on_done=pytest.fail, on_error=errors.append)
    pump(root, lambda: errors)
    root.destroy()
    assert isinstance(errors[0], ValueError)


def test_취소하면_취소_알림만_온다():
    root = tkinter.Toplevel(ROOT)
    cancelled_calls = []

    def work(progress, cancelled):
        while not cancelled():
            time.sleep(0.01)
        raise OperationCancelled()

    task = BackgroundTask(root, work, on_done=pytest.fail, on_error=pytest.fail,
                          on_cancelled=lambda: cancelled_calls.append(True))
    task.cancel()
    pump(root, lambda: cancelled_calls)
    root.destroy()
    assert cancelled_calls == [True]


# ── 되돌릴 수 없는 동작의 확인 창 ──

def _dialog():
    return ConfirmDialog(ROOT, "기준선 다시 만들기", "이미 기준선이 있습니다.", yes_text="새로 만들기", no_text="취소")


def test_확인_창은_예를_눌러야만_참():
    dialog = _dialog()
    dialog.yes_button.invoke()
    assert dialog.result is True


def test_확인_창에서_아니오를_누르면_거짓():
    dialog = _dialog()
    dialog.no_button.invoke()
    assert dialog.result is False


def test_확인_창을_그냥_닫으면_거짓():
    dialog = _dialog()
    dialog.close()
    assert dialog.result is False


def test_확인_창은_처음에_아니오에_초점이_있다():
    dialog = _dialog()
    ROOT.update()
    try:
        assert dialog.default_choice == "no"
    finally:
        dialog.close()
