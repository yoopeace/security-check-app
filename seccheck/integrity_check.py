"""파일 무결성 탭의 판정. file-integrity-checker(checker) 를 감싼다.

기준선(snapshot.json)·비밀키(integrity.key)·검사 기록(integrity_log.txt)은
검사 대상 폴더가 아니라 앱 전용 폴더의 '폴더별 칸'에 둔다:
  <앱 전용 폴더>/integrity/<폴더 경로의 해시 앞 16자리>/
"""

import hashlib
import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import checker

from seccheck.paths import app_data_dir
from seccheck.verdict import Finding, Level, overall

SNAPSHOT_NAME = "snapshot.json"
KEY_NAME = "integrity.key"
LOG_NAME = "integrity_log.txt"
FOLDER_NAME = "folder.txt"   # 이 칸이 어느 폴더의 것인지 사람이 알아볼 수 있게


@dataclass(frozen=True)
class IntegrityReport:
    level: Level
    findings: list            # Finding
    checked_count: int        # 기록하거나 검사한 파일 수


def integrity_dir_for(folder: str) -> Path:
    normalized = os.path.normcase(os.path.abspath(folder))
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return app_data_dir() / "integrity" / digest


def _tool_files(store: Path, key_file: str | None) -> checker.ToolFiles:
    return checker.ToolFiles(snapshot=str(store / SNAPSHOT_NAME), log=str(store / LOG_NAME),
                             key=key_file or str(store / KEY_NAME))


@contextmanager
def _log_to(path: Path):
    """checker 의 검사 기록을 이 폴더 칸의 기록 파일에만 남긴다.

    logging.basicConfig 는 프로그램에서 한 번만 적용되므로, 여러 폴더를 차례로 검사하면
    기록이 첫 폴더 파일에 섞인다. 그래서 호출마다 기록 파일을 붙였다 뗀다.
    """
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)s  %(message)s"))
    previous_level = checker.log.level
    checker.log.addHandler(handler)
    checker.log.setLevel(logging.INFO)
    try:
        yield
    finally:
        checker.log.removeHandler(handler)
        checker.log.setLevel(previous_level)
        handler.close()


def _report(findings: list, checked_count: int = 0) -> IntegrityReport:
    findings = sorted(findings, key=lambda f: -f.level)
    return IntegrityReport(overall(findings), findings, checked_count)


def _check(message: str) -> Finding:
    return Finding(Level.CHECK, message)


def make_baseline(folder: str, replace: bool = False, key_file: str | None = None) -> IntegrityReport:
    if not os.path.isdir(folder):
        return _report([_check(f"폴더를 찾을 수 없습니다: {checker.safe_path(folder)}")])
    store = integrity_dir_for(folder)
    tool_files = _tool_files(store, key_file)
    # 변조된 뒤에 기준선을 새로 만들면 변조가 정상으로 기록된다. 덮어쓰기는 확인을 받은 뒤에만.
    if Path(tool_files.snapshot).exists() and not replace:
        return _report([_check("이미 기준선이 있습니다. 새로 만들면 이전 기준이 사라집니다.")])

    store.mkdir(parents=True, exist_ok=True)
    (store / FOLDER_NAME).write_text(os.path.abspath(folder), encoding="utf-8")
    with _log_to(store / LOG_NAME):
        outcome = checker.make_snapshot(folder, (), tool_files)

    if outcome.failure == "scan_incomplete":
        return _report([_check("읽지 못한 파일이 있어 기준선을 만들지 않았습니다. 권한을 확인해 주세요.")]
                       + [_check(f"확인하지 못한 파일: {checker.safe_path(p)}") for p in outcome.detail])
    if outcome.failure == "key_unavailable":
        return _report([_check(f"비밀키를 사용할 수 없어 기준선을 만들지 않았습니다: {checker.safe_path(tool_files.key)}")])
    if outcome.failure == "save_failed":
        return _report([_check("기준선을 저장하지 못했습니다. 이전 기준선이 있었다면 그대로 남아 있습니다.")])
    if outcome.failure is not None:   # target_missing: 위에서 확인했지만 그 사이 폴더가 사라진 경우
        return _report([_check(f"폴더를 찾을 수 없습니다: {checker.safe_path(folder)}")])

    findings = [Finding(Level.OK, f"기준선을 만들었습니다: 파일 {outcome.saved_count}개")]
    if outcome.key_created and key_file:
        findings.append(Finding(Level.OK, f"새 비밀키를 만들었습니다: {checker.safe_path(key_file)}. "
                                          "이 키가 있어야 검사할 수 있습니다."))
    return _report(findings, outcome.saved_count)


REJECTION_MESSAGES = {
    "missing": "이 폴더의 기준선이 없습니다. 먼저 기준선을 만들어 주세요.",
    "unreadable": "기준선 파일이 손상되어 검사할 수 없습니다. 기준선을 다시 만들어 주세요.",
    "malformed": "기준선 파일이 손상되어 검사할 수 없습니다. 기준선을 다시 만들어 주세요.",
    "unsigned": "서명이 없는 기준선이라 믿을 수 없습니다. 기준선을 다시 만들어 주세요.",
    "signature_mismatch": "기준선과 비밀키가 맞지 않습니다. 기준선이 조작되었거나 다른 비밀키를 지정했을 수 있습니다.",
}


def verify(folder: str, key_file: str | None = None) -> IntegrityReport:
    if not os.path.isdir(folder):
        return _report([_check(f"폴더를 찾을 수 없습니다: {checker.safe_path(folder)}")])
    store = integrity_dir_for(folder)
    tool_files = _tool_files(store, key_file)
    if not Path(tool_files.snapshot).exists():
        # 기준선이 없으면 앱 전용 폴더에도 아무것도 만들지 않는다
        return _report([_check(REJECTION_MESSAGES["missing"])])

    with _log_to(store / LOG_NAME):
        outcome = checker.run_verification(folder, None, False, tool_files)

    refusal = outcome.refusal
    if refusal is not None:
        if refusal.kind == "snapshot_rejected":
            reason = refusal.detail.reason
            if reason == "key_missing":
                return _report([_check(f"비밀키가 없어 기준선을 확인할 수 없습니다: {checker.safe_path(tool_files.key)}")])
            if reason == "key_unusable":
                return _report([_check(f"비밀키를 사용할 수 없습니다: {checker.safe_path(tool_files.key)}")])
            return _report([_check(REJECTION_MESSAGES.get(reason, "기준선을 믿을 수 없어 검사를 멈췄습니다."))])
        if refusal.kind == "target_missing":
            return _report([_check(f"폴더를 찾을 수 없습니다: {checker.safe_path(folder)}")])
        return _report([_check("기준선의 설정이 지금 검사와 달라 검사를 멈췄습니다. 기준선을 다시 만들어 주세요.")])

    result = outcome.comparison
    name = checker.safe_path
    findings = ([Finding(Level.DANGER, f"바뀐 파일: {name(p)}") for p in result.modified]
                + [Finding(Level.DANGER, f"사라진 파일: {name(p)}") for p in result.deleted]
                + [Finding(Level.DANGER, f"새로 생긴 파일: {name(p)}") for p in result.added]
                + [_check(f"확인하지 못한 파일: {name(p)}") for p in result.unverifiable])
    if not findings:
        findings = [Finding(Level.OK, f"기준선과 모두 같습니다: 파일 {outcome.scanned_count}개")]
    return _report(findings, outcome.scanned_count)
