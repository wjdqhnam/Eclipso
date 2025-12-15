from __future__ import annotations

import io
import re
from typing import List, Optional, Set, Dict, Tuple
from bisect import bisect_right

import fitz
import logging

try:
    import pymupdf4llm  # type: ignore
except Exception:
    pymupdf4llm = None  # type: ignore

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS

try:
    from .common import cleanup_text, compile_rules
except Exception:  # pragma: no cover
    from server.modules.common import cleanup_text, compile_rules  # type: ignore

log_prefix = "[PDF]"
logger = logging.getLogger(__name__)

_WS_RE = re.compile(r"\s+", re.UNICODE)


def _compact_ws(s: str) -> str:
    return _WS_RE.sub(" ", (s or "").strip())


def _strip_ws(s: str) -> str:
    return _WS_RE.sub("", (s or "").strip())


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
        return {"full_text": full_text, "pages": pages}
    finally:
        doc.close()


def extract_markdown(pdf_bytes: bytes, by_page: bool = True) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        if pymupdf4llm is None:
            pages: list[dict] = []
            chunks: list[str] = []
            for idx, page in enumerate(doc, start=1):
                raw = page.get_text("text") or ""
                cleaned = cleanup_text(raw)
                md = cleaned
                pages.append({"page": idx, "markdown": md, "tables": []})
                if md:
                    chunks.append(md)
            return {"markdown": "\n\n".join(chunks), "pages": pages if by_page else []}

        if by_page:
            chunks = pymupdf4llm.to_markdown(doc=doc, page_chunks=True)
            pages: list[dict] = []
            for idx, ch in enumerate(chunks, start=1):
                meta = ch.get("metadata", {}) or {}
                page_no = meta.get("page_number") or idx
                md = (ch.get("text", "") or "").replace("<br>", "")
                pages.append({"page": page_no, "markdown": md, "tables": []})
            full_md = "\n\n".join(p["markdown"] for p in pages if p["markdown"])
            return {"markdown": full_md, "pages": pages}

        md = (pymupdf4llm.to_markdown(doc=doc) or "").replace("<br>", "")
        return {"markdown": md, "pages": []}
    finally:
        doc.close()


def _normalize_pattern_names(patterns: List[PatternItem] | None) -> Optional[Set[str]]:
    if not patterns:
        return None
    names: Set[str] = set()
    for p in patterns:
        nm = getattr(p, "name", None) or getattr(p, "rule", None)
        if nm:
            names.add(nm)
    return names or None



def _search_chars_exact(page: fitz.Page, target: str) -> List[fitz.Rect]:
    target = (target or "").strip()
    if not target:
        return []

    try:
        raw = page.get_text("rawdict")
    except Exception:
        return []

    chars: List[dict] = []
    line_id = 0

    for block in raw.get("blocks", []):
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                for ch in span.get("chars", []):
                    c = ch.get("c", "")
                    if c:
                        chars.append(
                            {
                                "c": c,
                                "bbox": fitz.Rect(ch["bbox"]),
                                "line_id": line_id,
                            }
                        )
            line_id += 1

    if not chars:
        return []

    seq = "".join(ch["c"] for ch in chars)
    seq_cf = seq.casefold()
    target_cf = target.casefold()

    rects: List[fitz.Rect] = []
    idx0 = 0

    while True:
        idx = seq_cf.find(target_cf, idx0)
        if idx < 0:
            break

        end = idx + len(target)
        if end > len(chars):
            break
        cur_line = chars[idx]["line_id"]
        cur_rect = fitz.Rect(chars[idx]["bbox"])

        for i in range(idx + 1, end):
            li = chars[i]["line_id"]
            if li != cur_line:
                rects.append(cur_rect)
                cur_line = li
                cur_rect = fitz.Rect(chars[i]["bbox"])
            else:
                cur_rect |= chars[i]["bbox"]

        rects.append(cur_rect)

        idx0 = idx + 1

    return rects


# 공백 허용 fallback
def _search_with_whitespace_fallback(page: fitz.Page, val: str) -> List[fitz.Rect]:
    if not val:
        return []

    val = (val or "").replace("\u200b", "").replace("\ufeff", "")

    def _safe_search_for(q: str) -> List[fitz.Rect]:
        if not q:
            return []
        try:
            return page.search_for(q) or []
        except Exception:
            return []

    # 1) char-level 정확 검색
    rects = _search_chars_exact(page, val)
    if rects:
        return rects

    # 2) 기본 search_for
    rects = _safe_search_for(val)
    if rects:
        return rects

    # 3) compact whitespace
    compact = re.sub(r"[\s\r\n]+", " ", val.strip())
    if compact and compact != val:
        rects = _safe_search_for(compact)
        if rects:
            return rects

    # 4) 공백 완전 제거
    nospace = re.sub(r"[\s\r\n]+", "", val.strip())
    if nospace:
        rects = _search_chars_exact(page, nospace)
        if rects:
            return rects

    return []

def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem] | None) -> List[Box]:
    comp = compile_rules()
    allowed_names = _normalize_pattern_names(patterns)

    logger.info("%s detect_boxes_from_patterns: allowed=%s", log_prefix, allowed_names)

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []
    try:
        for pno, page in enumerate(doc):
            text = page.get_text("text") or ""
            if not text:
                continue

            for (rule_name, rx, need_valid, _prio, validator) in comp:
                if allowed_names is not None and rule_name not in allowed_names:
                    continue
                for m in rx.finditer(text):
                    val = m.group(0)
                    if not val:
                        continue
                    rects = _search_with_whitespace_fallback(page, val)
                    for r in rects:
                        boxes.append(Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
    finally:
        doc.close()
    return boxes

def _fill_color(fill: str):
    f = (fill or "black").strip().lower()
    return (0, 0, 0) if f == "black" else (1, 1, 1)


def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        color = _fill_color(fill)
        for b in boxes:
            page = doc.load_page(int(b.page))
            rect = fitz.Rect(float(b.x0), float(b.y0), float(b.x1), float(b.y1))
            page.add_redact_annot(rect, fill=color)
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

    def _strip_md_noise(s: str) -> str:
        if not s:
            return ""
        s = s.replace("\u00a0", " ")
        s = re.sub(r"[`*_>#|]", " ", s)
        return s.strip()

    if extra_spans:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            for i, span in enumerate(extra_spans):
                raw_text = span.get("text", "")
                span_text = _strip_md_noise(raw_text)

                if i < 20:
                    logger.info(
                        "%s EXTRA_SPAN[%d] page=%s label=%s start=%s end=%s raw=%r cleaned=%r",
                        log_prefix,
                        i,
                        span.get("page"),
                        span.get("label"),
                        span.get("start"),
                        span.get("end"),
                        (raw_text or "")[:60],
                        (span_text or "")[:60],
                    )

                if not span_text:
                    continue

                page_hint = span.get("page")
                page_order = list(range(len(doc)))
                if isinstance(page_hint, int):
                    p0 = page_hint - 1
                    if 0 <= p0 < len(doc):
                        page_order = [p0] + [j for j in page_order if j != p0]

                found = False
                for pidx in page_order:
                    page = doc[pidx]
                    rects = _search_with_whitespace_fallback(page, span_text)
                    if not rects:
                        continue
                    for r in rects:
                        boxes.append(Box(page=pidx, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
                    found = True
                    break

                if not found:
                    logger.warning("%s span text not found: %r", log_prefix, span_text[:60])
        finally:
            doc.close()


    return apply_redaction(pdf_bytes, boxes)


def extract_table_layout(pdf_bytes: bytes) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    tables: List[dict] = []
    try:
        for page_idx, page in enumerate(doc):
            try:
                finder = page.find_tables()
            except Exception:
                continue

            if not finder or not getattr(finder, "tables", None):
                continue

            for t in finder.tables:
                try:
                    bbox = getattr(t, "bbox", None)
                    if not bbox:
                        continue
                    rect = fitz.Rect(bbox)

                    row_count = getattr(t, "row_count", None)
                    col_count = getattr(t, "col_count", None)

                    tables.append(
                        {
                            "page": page_idx + 1,
                            "bbox": [rect.x0, rect.y0, rect.x1, rect.y1],
                            "row_count": int(row_count) if row_count is not None else None,
                            "col_count": int(col_count) if col_count is not None else None,
                        }
                    )
                except Exception:
                    continue
    finally:
        doc.close()

    return {"tables": tables}
