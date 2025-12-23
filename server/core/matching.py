from __future__ import annotations
import re
from typing import List, Tuple
from server.modules.common import compile_rules 


def _is_valid(value: str, validator) -> bool:
    """
    RULES 에 정의된 validator 호출 헬퍼.
    - validator(v)
    - 또는 validator(v, opts) 두 가지 시그니처 모두 지원.
    """
    if not callable(validator):
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            # (value, opts) 형태인 validator 대응
            return bool(validator(value, None))
    except Exception:
        # 검증 중 예외가 나면 보수적으로 "유효하지 않음"으로 본다.
        return False


def find_sensitive_spans(text: str) -> List[Tuple[int, int, str, str]]:
    """
    공용 정규식 + validator 기반 민감정보 매칭

    - PRESET_PATTERNS + RULES 를 compile_rules() 로 컴파일해서 사용
    - validator 가 걸려 있는 룰은 유효성 검증에 실패하면 결과에서 아예 제외
    """
    if not isinstance(text, str):
        text = str(text)

    results: List[Tuple[int, int, str, str]] = []

    # PRESET_PATTERNS + RULES 통합 컴파일
    comp = compile_rules()

    for name, rx, need_valid, _prio, validator in comp:
        if rx is None:
            continue

        for m in rx.finditer(text):
            value = m.group(0)
            # validator 검사
            if need_valid and not _is_valid(value, validator):
                # 유효하지 않은 후보 → 결과에서 완전히 제외
                continue

            results.append((m.start(), m.end(), value, name))

    print(f"[core.matching] 총 {len(results)}개 매칭")
    return results
