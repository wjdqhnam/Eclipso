from __future__ import annotations

import io
import re
from typing import List, Optional, Set, Dict

import fitz
import pymupdf4llm
import logging 

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS, RULES
from server.modules.ner_module import run_ner
from server.core.regex_utils import match_text


try:
    from .common import cleanup_text, compile_rules
except Exception:  # pragma: no cover
    from server.modules.common import cleanup_text, compile_rules  # type: ignore


log_prefix = "[PDF]"
logger = logging.getLogger(__name__) 


# /text/extract 용 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
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


# 표 구조 추출(페이지, 위치, 행/열 개수)
def extract_table_layout(pdf_bytes: bytes) -> dict:

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    tables: list[dict] = []

    try:
        for page_idx, page in enumerate(doc):
            finder = page.find_tables()  # TableFinder 객체

            if not finder or not finder.tables:
                continue

            for t in finder.tables:
                # t.bbox 가 Rect 이든 tuple 이든 상관없이 Rect 로 강제 변환
                rect = fitz.Rect(t.bbox)

                tables.append(
                    {
                        "page": page_idx + 1,  # 1-based
                        "bbox": [rect.x0, rect.y0, rect.x1, rect.y1],
                        "row_count": t.row_count,
                        "col_count": t.col_count,
                    }
                )
    finally:
        doc.close()

    return {"tables": tables}


#마크다운
def extract_markdown(pdf_bytes: bytes, by_page: bool = True) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        if by_page:
            chunks = pymupdf4llm.to_markdown(
                doc=doc,
                page_chunks=True,
            )

            pages: list[dict] = []

            for idx, ch in enumerate(chunks, start=1):
                meta = ch.get("metadata", {}) or {}
                page_no = meta.get("page_number") or idx

                md = ch.get("text", "") or ""
                md = md.replace("<br>", "")

                raw_tables = ch.get("tables", []) or []
                tables: list[dict] = []
                for t in raw_tables:
                    bbox = t.get("bbox")
                    rows = t.get("rows") or t.get("row_count")
                    cols = t.get("columns") or t.get("col_count")
                    if not bbox or rows is None or cols is None:
                        continue
                    tables.append(
                        {
                            "bbox": list(bbox),
                            "row_count": int(rows),
                            "col_count": int(cols),
                        }
                    )

                pages.append(
                    {
                        "page": page_no,
                        "markdown": md,
                        "tables": tables,
                    }
                )

            full_md = "\n\n".join(
                p["markdown"] for p in pages if p["markdown"]
            )

            return {
                "markdown": full_md,
                "pages": pages,
            }

        else:
            md = pymupdf4llm.to_markdown(doc=doc)
            md = md.replace("<br>", "\n")
            return {
                "markdown": md,
                "pages": [],
            }
    finally:
        doc.close()


# 헬퍼들
def _normalize_pattern_names(
    patterns: List[PatternItem] | None,
) -> Optional[Set[str]]:
    if not patterns:
        return None

    names: Set[str] = set()
    for p in patterns:
        nm = getattr(p, "name", None) or getattr(p, "rule", None)
        if nm:
            names.add(nm)
    return names or None


def _is_valid_value(need_valid: bool, validator, value: str) -> bool:
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


# PDF 내 박스 탐지
def detect_boxes_from_patterns(
    pdf_bytes: bytes,
    patterns: List[PatternItem] | None,
) -> List[Box]:
    comp = compile_rules()
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
                        "page=",
                        pno + 1,
                        "rule=",
                        rule_name,
                        "need_valid=",
                        need_valid,
                        "ok=",
                        ok,
                        "value=",
                        repr(val),
                    )

                    # FAIL 이면 박스 만들지 않음
                    if not ok:
                        continue

                    # 실제 박스 찾기
                    rects = page.search_for(val)
                    for r in rects:
                        print(
                            f"{log_prefix} BOX",
                            "page=",
                            pno + 1,
                            "rule=",
                            rule_name,
                            "rect=",
                            (r.x0, r.y0, r.x1, r.y1),
                        )
                        boxes.append(
                            Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1)
                        )
    finally:
        doc.close()

    print(
        f"{log_prefix} detect summary",
        "OK=",
        {k: v for k, v in sorted(stats_ok.items())},
        "FAIL=",
        {k: v for k, v in sorted(stats_fail.items())},
        "boxes=",
        len(boxes),
    )

    return boxes


# 레닥션 적용
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

        # 페이지 단위로 실제 레닥션 적용
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

    # extra_spans (NER 결과 등) 처리
    if extra_spans:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            # file_redact_api.py와 동일한 방식으로 텍스트 추출
            # "\n".join([p.get_text("text") or "" for p in doc])
            page_texts = []
            page_offsets = []  # 각 페이지의 전체 텍스트에서의 시작 위치
            current_offset = 0

            for page in doc:
                text = page.get_text("text") or ""
                page_texts.append(text)
                page_offsets.append(current_offset)
                # 페이지 구분자: \n (file_redact_api.py와 동일)
                current_offset += len(text) + 1  # +1 for \n

            # 전체 텍스트 (file_redact_api.py와 동일한 형식)
            full_text = "\n".join(page_texts)

            # 각 span을 PDF 좌표로 변환
            for span in extra_spans:
                start = span.get("start", 0)
                end = span.get("end", 0)
                if end <= start or start >= len(full_text):
                    continue

                # span의 텍스트 추출
                span_text = full_text[start : min(end, len(full_text))]
                if not span_text or not span_text.strip():
                    continue

                # span이 속한 페이지 찾기
                for page_idx, page_offset in enumerate(page_offsets):
                    next_offset = (
                        page_offsets[page_idx + 1]
                        if page_idx + 1 < len(page_offsets)
                        else len(full_text)
                    )

                    # span이 이 페이지 범위에 있는지 확인
                    if start >= page_offset and start < next_offset:
                        # 페이지 텍스트에서 span 텍스트 찾기
                        search_text = span_text.strip()
                        if not search_text:
                            continue

                        # 페이지에서 텍스트 검색
                        page = doc[page_idx]
                        rects = page.search_for(search_text)

                        if rects:
                            # 모든 매칭 위치에 박스 추가
                            for r in rects:
                                boxes.append(
                                    Box(
                                        page=page_idx,
                                        x0=r.x0,
                                        y0=r.y0,
                                        x1=r.x1,
                                        y1=r.y1,
                                    )
                                )

                            print(
                                f"{log_prefix} NER BOX",
                                "page=",
                                page_idx + 1,
                                "label=",
                                span.get("label", "unknown"),
                                "text=",
                                repr(search_text[:50]),
                                "matches=",
                                len(rects),
                            )
                        break
        finally:
            doc.close()

    return apply_redaction(pdf_bytes, boxes)