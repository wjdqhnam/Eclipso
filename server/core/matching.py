import re
from typing import List, Tuple, Dict
from server.core.redaction_rules import PRESET_PATTERNS

def find_sensitive_spans(text: str) -> List[Tuple[int, int, str, str]]:
    """
    공용 정규식 매칭 엔진.
    PRESET_PATTERNS 기반으로 (start, end, value, pattern_name) 리스트 반환.
    """
    results: List[Tuple[int, int, str, str]] = []

    for rule in PRESET_PATTERNS:
        name = rule.get("name", "")
        regex_pattern = rule.get("regex")
        if not regex_pattern:
            continue
        try:
            regex = re.compile(regex_pattern, re.IGNORECASE)
        except re.error:
            print(f"[WARN] 정규식 오류: {name}")
            continue

        for m in regex.finditer(text):
            results.append((m.start(), m.end(), m.group(0), name))

    print(f"[core.matching] 총 {len(results)}개 매칭")
    return results
