from __future__ import annotations
import io, zipfile
from typing import List, Tuple

# common 유틸 임포트: 상대 경로 우선, 실패 시 절대 경로 fallback 
try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        chart_rels_sanitize,
    )
except Exception:  # pragma: no cover - 패키지 구조 달라졌을 때 대비
    from server.modules.common import (  # type: ignore
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        chart_rels_sanitize,
    )

# schemas 임포트: core 우선, 실패 시 대안 경로 시도
try:
    from ..core.schemas import XmlMatch, XmlLocation  # 일반적인 현재 리포 구조
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation   # 일부 브랜치/옛 구조
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  # 절대경로 fallback


# RULES(validator) 접근
try:
    from ..core.redaction_rules import RULES
except Exception:
    try:
        from ..redaction_rules import RULES  # type: ignore
    except Exception:
        from server.core.redaction_rules import RULES  # type: ignore


def xlsx_text(zipf: zipfile.ZipFile) -> str:
    return xlsx_text_from_zip(zipf)


# /text/extract, /redactions/xml/scan 에서 사용하는 래퍼
def extract_text(file_bytes: bytes) -> dict:
    """바이트로 들어온 XLSX에서 텍스트만 추출."""
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = xlsx_text(zipf)
    return {
        "full_text": txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


def _get_validator(rule_name: str):
    v = None
    try:
        v = RULES.get(rule_name, {}).get("validator")
    except Exception:
        v = None
    return v if callable(v) else None


# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보를 추출
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            # tuple/list 계열
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 3:
                    rule_name, rx, need_valid = ent[0], ent[1], bool(ent[2])
                elif len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                    need_valid = True
                else:
                    continue
            else:
                # 네임드 객체(SimpleNamespace 등)
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
                need_valid = bool(getattr(ent, "need_valid", True))
            if rx is None:
                continue
        except Exception:
            continue

        validator = _get_validator(rule_name)

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and validator:
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False  # 검증 예외는 실패로 간주

            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(kind="xlsx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "xlsx", text


# 파일 단위 레닥션: 시트/공유문자열/차트/차트.rels 처리
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 1) 셀/공유문자열: 텍스트 노드 마스킹
    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        b, _ = sub_text_nodes(data, comp)
        return b

    # 2) 차트 본문: a:t, c:strCache 라벨 마스킹 (+ 남은 텍스트 노드 안전망)
    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return b2

    # 3) 차트 관계(.rels)
    if low.startswith("xl/charts/_rels/") and low.endswith(".rels"):
        b3, _ = chart_rels_sanitize(data)
        return b3

    # 4) 기타 파트는 원본 유지
    return data
