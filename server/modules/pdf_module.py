# server/modules/pdf_module.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import re
from typing import List, Optional, Set, Dict

import fitz  # PyMuPDF

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS, RULES
from server.modules.ner_module import run_ner  # 앞으로 쓸 수도 있으니 그대로 둠
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY
from server.core.regex_utils import match_text

# 공통 유틸: 텍스트 정리 + 규칙 컴파일(validator 포함)
try:
    from .common import cleanup_text, compile_rules
except Exception:  # pragma: no cover
    from server.modules.common import cleanup_text, compile_rules  # type: ignore


log_prefix = "[PDF]"


# ─────────────────────────────────────────────────────────────
# /text/extract 용 텍스트 추출
# ─────────────────────────────────────────────────────────────
def extract_text(file_bytes: bytes) -> dict:
    """
    PDF에서 텍스트를 추출해 /text/extract 형식으로 반환.

    {
      "full_text": "...",
      "pages": [
        {"page": 1, "text": "..."},
        ...
      ]
    }
    """
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    try:
        pages = []
        all_chunks: List[str] = []

        for idx, page in enumerate(doc):
            raw = page.get_text("text") or ""
            cleaned = cleanup_text(raw)
            pages.append({"page": idx + 1, "text": cleaned})
            if cleaned:
                all_chunks.append(cleaned)

        full_text = cleanup_text("\n\n".join(all_chunks))

        return {
            "full_text": full_text,
            "pages": pages,
        }
    finally:
        doc.close()


# ─────────────────────────────────────────────────────────────
# 헬퍼들
# ─────────────────────────────────────────────────────────────
def _normalize_pattern_names(
    patterns: List[PatternItem] | None,
) -> Optional[Set[str]]:
    """
    /redactions/pdf/scan 에서 넘어온 patterns 는 PRESET 기반이므로
    이름만 추려서 서버쪽 compile_rules 결과를 필터링하는 데만 쓴다.
    (regex 문자열은 서버 PRESET 과 동일하다고 가정하고 무시)
    """
    if not patterns:
        return None

    names: Set[str] = set()
    for p in patterns:
        nm = getattr(p, "name", None) or getattr(p, "rule", None)
        if nm:
            names.add(nm)
    return names or None


def _is_valid_value(need_valid: bool, validator, value: str) -> bool:
    """
    compile_rules() 가 넘겨준 need_valid / validator 를 그대로 사용.
    - need_valid == False → validator 무시, 항상 OK
    - need_valid == True  → validator 가 있으면 돌려서 True 일 때만 OK
    """
    if not need_valid or not callable(validator):
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            # validator(val, ctx) 형태일 수도 있음
            return bool(validator(value, None))
    except Exception:
        # validator 내부 예외는 FAIL 처리
        print(f"{log_prefix} VALIDATOR ERROR", repr(value))
        return False


# ─────────────────────────────────────────────────────────────
# PDF 내 박스 탐지
#  - compile_rules() 기반 + validator 결과를 그대로 사용
#  - FAIL(validator False) 인 값은 **절대로 박스 만들지 않음**
# ─────────────────────────────────────────────────────────────
def detect_boxes_from_patterns(
    pdf_bytes: bytes,
    patterns: List[PatternItem] | None,
) -> List[Box]:
    """
    patterns:
      - None        → 서버 PRESET 전체 사용
      - PatternItem → name 만 사용해서 subset 필터링
    """
    # 1) 서버 기준 규칙(validator 포함) 가져오기
    comp = compile_rules()  # [(name, rx, need_valid, prio, validator), ...]
    allowed_names = _normalize_pattern_names(patterns)

    print(
        f"{log_prefix} detect_boxes_from_patterns: rules 준비 완료",
        "allowed_names=",
        sorted(allowed_names) if allowed_names else "ALL",
    )

    # 룰별 OK/FAIL 카운터 (디버깅용)
    stats_ok: Dict[str, int] = {}
    stats_fail: Dict[str, int] = {}

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    try:
        for pno, page in enumerate(doc):
            text = page.get_text("text") or ""
            if not text:
                continue

            for (rule_name, rx, need_valid, _prio, validator) in comp:
                if allowed_names and rule_name not in allowed_names:
                    continue

                try:
                    it = rx.finditer(text)
                except Exception:
                    continue

                for m in it:
                    val = m.group(0)
                    if not val:
                        continue

                    ok = _is_valid_value(need_valid, validator, val)

                    # 통계
                    if ok:
                        stats_ok[rule_name] = stats_ok.get(rule_name, 0) + 1
                    else:
                        stats_fail[rule_name] = stats_fail.get(rule_name, 0) + 1

                    print(
                        f"{log_prefix} MATCH",
                        "page=", pno + 1,
                        "rule=", rule_name,
                        "need_valid=", need_valid,
                        "ok=", ok,
                        "value=", repr(val),
                    )

                    # FAIL 이면 박스 만들지 않음
                    if not ok:
                        continue

                    # 실제 박스 찾기
                    rects = page.search_for(val)
                    for r in rects:
                        print(
                            f"{log_prefix} BOX",
                            "page=", pno + 1,
                            "rule=", rule_name,
                            "rect=", (r.x0, r.y0, r.x1, r.y1),
                        )
                        boxes.append(
                            Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1)
                        )
    finally:
        doc.close()

    print(
        f"{log_prefix} detect summary",
        "OK=", {k: v for k, v in sorted(stats_ok.items())},
        "FAIL=", {k: v for k, v in sorted(stats_fail.items())},
        "boxes=", len(boxes),
    )

    return boxes


# 레닥션 적용
# ─────────────────────────────────────────────────────────────
def _fill_color(fill: str):
    f = (fill or "black").strip().lower()
    return (0, 0, 0) if f == "black" else (1, 1, 1)


def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
    print(f"{log_prefix} apply_redaction: boxes=", len(boxes), "fill=", fill)
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        color = _fill_color(fill)
        for b in boxes:
            page = doc.load_page(int(b.page))
            rect = fitz.Rect(float(b.x0), float(b.y0), float(b.x1), float(b.y1))
            page.add_redact_annot(rect, fill=color)
        # 페이지 단위 적용
        for page in doc:
            page.apply_redactions()
        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()
    finally:
        doc.close()

def apply_text_redaction(pdf_bytes: bytes, extra_spans: list = None) -> bytes:
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    if not extra_spans:
        return apply_redaction(pdf_bytes, boxes)

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        # 기존 박스 우선 반영(주석만 추가)
        for b in boxes:
            page = doc.load_page(int(b.page))
            rect = fitz.Rect(float(b.x0), float(b.y0), float(b.x1), float(b.y1))
            page.add_redact_annot(rect, fill=(0, 0, 0))

        # 추가 스팬 반영
        for page in doc:
            for s in extra_spans:
                frag = (s.get("text_sample") or "").strip()
                if not frag:
                    continue
                rects = page.search_for(frag)
                for r in rects:
                    if s.get("decision") == "highlight":
                        annot = page.add_highlight_annot(r)
                        annot.set_colors(stroke=(1, 1, 0))
                        annot.set_opacity(0.45)
                        annot.update()
                    else:
                        page.add_redact_annot(r, fill=(0, 0, 0))

        # 페이지 단위 적용
        for page in doc:
            page.apply_redactions()

        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()
    finally:
        doc.close()


def apply_text_redaction(pdf_bytes: bytes, extra_spans: list | None = None) -> bytes:

    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    return apply_redaction(pdf_bytes, boxes)


def extract_text(pdf_bytes: bytes) -> str:
    if not pdf_bytes:
        return ""

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        if doc.needs_pass:
            raise RuntimeError("암호화된 PDF입니다")

        texts = []
        for page in doc:
            t = page.get_text("text") or ""
            texts.append(t)
        return "\n".join(texts)
    finally:
        doc.close()