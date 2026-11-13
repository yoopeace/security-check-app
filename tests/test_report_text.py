"""보고서 파일에 저장하는 문장"""

from datetime import datetime

from seccheck.integrity_check import IntegrityReport
from seccheck.log_check import KST, LogReport
from seccheck.report_text import render_integrity_report, render_log_report
from seccheck.verdict import Finding, Level

MADE_AT = datetime(2026, 11, 13, 14, 30, tzinfo=KST)


def test_로그_분석_보고서_형식():
    report = LogReport(Level.DANGER,
                       [Finding(Level.DANGER, "로그인 반복 실패(급속): 10.0.0.5 — 10분 안에 45회 (2026-11-13 10:02 ~ 10:05)"),
                        Finding(Level.CHECK, "계정이 잠겼습니다: admin (2026-11-13 10:06)")],
                       12345,
                       (datetime(2026, 11, 1, 9, 0, tzinfo=KST), datetime(2026, 11, 13, 14, 0, tzinfo=KST)))

    text = render_log_report(report, r"C:\증거\security.evtx", MADE_AT)

    assert text.splitlines() == [
        "=== 보안 점검 보고서 (로그 분석) ===",
        r"대상: C:\증거\security.evtx",
        "작성 시각: 2026-11-13 14:30",
        "판정: 위험 발견",
        "분석한 기록: 12,345건 (2026-11-01 09:00 ~ 2026-11-13 14:00)",
        "",
        "[위험] 로그인 반복 실패(급속): 10.0.0.5 — 10분 안에 45회 (2026-11-13 10:02 ~ 10:05)",
        "[확인] 계정이 잠겼습니다: admin (2026-11-13 10:06)",
    ]


def test_문제가_없으면_이상_없음과_근거를_적는다():
    report = LogReport(Level.OK, [], 300, (datetime(2026, 11, 1, 9, 0, tzinfo=KST), datetime(2026, 11, 2, 9, 0, tzinfo=KST)))
    lines = render_log_report(report, "security.evtx", MADE_AT).splitlines()
    assert lines[3:] == ["판정: 이상 없음", "분석한 기록: 300건 (2026-11-01 09:00 ~ 2026-11-02 09:00)", "", "발견된 문제가 없습니다."]


def test_기록이_없으면_기간_없이_0건():
    report = LogReport(Level.CHECK, [Finding(Level.CHECK, "보안 로그가 아닙니다.")], 0, None)
    assert "분석한 기록: 0건" in render_log_report(report, "x.evtx", MADE_AT).splitlines()


def test_무결성_보고서_형식():
    report = IntegrityReport(Level.DANGER, [Finding(Level.DANGER, "바뀐 파일: a.txt")], 3)

    lines = render_integrity_report(report, r"C:\증거\사진", "검사하기", MADE_AT).splitlines()

    assert lines == [
        "=== 보안 점검 보고서 (파일 무결성 - 검사하기) ===",
        r"대상 폴더: C:\증거\사진",
        "작성 시각: 2026-11-13 14:30",
        "판정: 위험 발견",
        "검사한 파일: 3개",
        "",
        "[위험] 바뀐 파일: a.txt",
    ]


def test_정상_결과_문장은_정상으로_표시한다():
    report = IntegrityReport(Level.OK, [Finding(Level.OK, "기준선과 모두 같습니다: 파일 3개")], 3)
    assert render_integrity_report(report, "docs", "검사하기", MADE_AT).splitlines()[-1] == "[정상] 기준선과 모두 같습니다: 파일 3개"
