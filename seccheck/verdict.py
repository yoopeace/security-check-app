"""판정 값.

화면에 보이는 판정은 세 가지뿐이다: 이상 없음 / 확인 필요 / 위험 발견.
쓰는 사람이 컴퓨터에 익숙하지 않은 동료 직원이므로, 기술 용어 대신 이 세 단계와
쉬운 문장(Finding.message)으로만 결과를 전한다.
"""

from dataclasses import dataclass
from enum import IntEnum


class Level(IntEnum):
    """판정 단계. 숫자가 클수록 심하다."""
    OK = 0
    CHECK = 1
    DANGER = 2

    @property
    def label(self) -> str:
        return {Level.OK: "이상 없음", Level.CHECK: "확인 필요", Level.DANGER: "위험 발견"}[self]


@dataclass(frozen=True)
class Finding:
    """판정 근거 한 줄."""
    level: Level
    message: str


def overall(findings: list[Finding]) -> Level:
    """가장 심한 단계가 전체 판정이 된다. 항목이 없으면 이상 없음."""
    return max((f.level for f in findings), default=Level.OK)
