"""판정 값: 위험 발견 / 확인 필요 / 이상 없음"""

from seccheck.verdict import Finding, Level, overall


def test_세_단계의_화면_문구():
    assert Level.OK.label == "이상 없음"
    assert Level.CHECK.label == "확인 필요"
    assert Level.DANGER.label == "위험 발견"


def test_항목이_없으면_이상_없음():
    assert overall([]) == Level.OK


def test_가장_심한_단계가_전체_판정이_된다():
    findings = [Finding(Level.CHECK, "계정이 잠겼습니다: admin"),
                Finding(Level.DANGER, "보안 로그가 삭제되었습니다")]
    assert overall(findings) == Level.DANGER


def test_확인_필요만_있으면_확인_필요():
    assert overall([Finding(Level.CHECK, "읽지 못한 기록이 1건 있습니다.")]) == Level.CHECK
