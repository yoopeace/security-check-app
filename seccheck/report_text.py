"""보고서 파일에 저장하는 문장. 상급자 보고나 기록 첨부용으로, 화면과 같은 쉬운 말로 쓴다."""

from datetime import datetime

from seccheck.integrity_check import IntegrityReport
from seccheck.log_check import LogReport
from seccheck.verdict import Level

TAGS = {Level.DANGER: "[위험]", Level.CHECK: "[확인]", Level.OK: "[정상]"}


def _minute(moment: datetime) -> str:
    return f"{moment:%Y-%m-%d %H:%M}"


def _items(findings) -> list[str]:
    if not findings:
        return ["발견된 문제가 없습니다."]
    return [f"{TAGS[f.level]} {f.message}" for f in findings]


def render_log_report(report: LogReport, source: str, made_at: datetime) -> str:
    basis = f"분석한 기록: {report.total:,}건"
    if report.period:
        basis += f" ({_minute(report.period[0])} ~ {_minute(report.period[1])})"
    lines = ["=== 보안 점검 보고서 (로그 분석) ===",
             f"대상: {source}",
             f"작성 시각: {_minute(made_at)}",
             f"판정: {report.level.label}",
             basis,
             "",
             *_items(report.findings)]
    return "\n".join(lines) + "\n"


def render_integrity_report(report: IntegrityReport, folder: str, action: str, made_at: datetime) -> str:
    lines = [f"=== 보안 점검 보고서 (파일 무결성 - {action}) ===",
             f"대상 폴더: {folder}",
             f"작성 시각: {_minute(made_at)}",
             f"판정: {report.level.label}",
             f"검사한 파일: {report.checked_count:,}개",
             "",
             *_items(report.findings)]
    return "\n".join(lines) + "\n"
