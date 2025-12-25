from __future__ import annotations
import re
from typing import List, Tuple
try:
    from ..modules.common import compile_rules
except Exception:  # pragma: no cover
    from server.modules.common import compile_rules  # type: ignore


def _is_valid(value: str, validator) -> bool:
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
