from __future__ import annotations

import io
import os
import re
import tempfile
from typing import List, Optional, Set, Dict, Tuple, Any

import fitz
import logging

try:
    import pymupdf4llm  # type: ignore
except Exception:
    pymupdf4llm = None  # type: ignore

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS, RULES
from server.core.regex_utils import match_text

try:
    from .common import cleanup_text, compile_rules
except Exception:  # pragma: no cover
    from server.modules.common import cleanup_text, compile_rules  # type: ignore


log_prefix = "[PDF]"
logger = logging.getLogger(__name__)

def _pdf_extract_debug_enabled() -> bool:
    return os.getenv("ECLIPSO_PDF_EXTRACT_DEBUG", "0") == "1"

def _vis_ws(s: str) -> str:
    if not isinstance(s, str):
        s = str(s)
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    s = s.replace("\n", "\\n\n")
    return s


def _compact_ws(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").replace("\u00a0", " ")).strip()


def extract_text(file_bytes: bytes) -> dict:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    try:
        pages = []
        all_chunks: List[str] = []

        for idx, page in enumerate(doc):
            raw = page.get_text("text") or ""
            cleaned = cleanup_text(raw)
            pages.append({"page": idx + 1, "text": cleaned})
            all_chunks.append(cleaned)

        return {"pages": pages, "full_text": "\n".join(all_chunks).strip()}
    finally:
        doc.close()


def _group_words_to_lines(words: list, y_tol: float = 2.0) -> list[list]:
    if not words:
        return []
    ws = []
    for w in words:
        try:
            x0, y0, x1, y1, txt = w[0], w[1], w[2], w[3], w[4]
        except Exception:
            continue
        if not txt:
            continue
        yc = (float(y0) + float(y1)) / 2.0
        ws.append((yc, float(x0), float(x1), float(y0), float(y1), str(txt)))
    ws.sort(key=lambda t: (t[0], t[1]))

    lines: list[list] = []
    cur: list = []
    cur_y: float | None = None
    for yc, x0, x1, y0, y1, txt in ws:
        if cur_y is None or abs(yc - cur_y) <= y_tol:
            cur.append((x0, x1, y0, y1, txt))
            cur_y = yc if cur_y is None else (cur_y + yc) / 2.0
        else:
            lines.append(cur)
            cur = [(x0, x1, y0, y1, txt)]
            cur_y = yc
    if cur:
        lines.append(cur)
    return lines


def _append_token(
    out_chars: list,
    out_text_parts: list,
    token: str,
    bbox: Tuple[float, float, float, float] | None,
    line_id: int,
) -> None:
    if not token:
        return
    out_text_parts.append(token)
    for _ch in token:
        out_chars.append({"bbox": bbox, "line_id": line_id})


def _words_lines_to_text_and_chars(
    lines: list[list],
    *,
    join_lines_with_space: bool,
    gap_x_tol: float = 1.5,
    line_id_start: int = 0,
    line_sep_override: str | None = None,
) -> Tuple[str, list, int]:
    out_parts: list[str] = []
    out_chars: list[dict] = []
    line_id = line_id_start

    for li, line in enumerate(lines):
        line_sorted = sorted(line, key=lambda t: t[0])
        prev_x1: float | None = None
        for _wi, (x0, x1, y0, y1, txt) in enumerate(line_sorted):
            bbox = (float(x0), float(y0), float(x1), float(y1))

            if prev_x1 is not None:
                if float(x0) - float(prev_x1) > float(gap_x_tol):
                    _append_token(out_chars, out_parts, " ", None, line_id)

            _append_token(out_chars, out_parts, txt, bbox, line_id)
            prev_x1 = float(x1)

        if li != len(lines) - 1:
            if line_sep_override is not None:
                sep = line_sep_override
            else:
                sep = " " if join_lines_with_space else "\n"
            _append_token(out_chars, out_parts, sep, None, line_id)
            if sep == "\n":
                line_id += 1

    return ("".join(out_parts), out_chars, line_id + 1)


def _table_to_text_and_chars(page: fitz.Page, table: Any, line_id_start: int = 0) -> Tuple[str, list, int]:
    out_parts: list[str] = []
    out_chars: list[dict] = []
    line_id = line_id_start

    rows = getattr(table, "rows", None)
    if not rows:
        try:
            extracted = table.extract()
        except Exception:
            extracted = None

        if extracted:
            for row in extracted:
                for cell_txt in row:
                    cell_s = str(cell_txt or "")
                    _append_token(out_chars, out_parts, cell_s, None, line_id)
                    _append_token(out_chars, out_parts, "\n", None, line_id)
                    line_id += 1
            return ("".join(out_parts), out_chars, line_id)

        return ("", [], line_id_start)

    for row in rows:
        cells = getattr(row, "cells", None) or []
        for cell in cells:
            if not cell:
                continue
            rect = fitz.Rect(cell)
            words = page.get_text("words", clip=rect) or []
            lines = _group_words_to_lines(words, y_tol=2.0)
            cell_text, cell_chars, _ = _words_lines_to_text_and_chars(
                lines,
                join_lines_with_space=True,
                gap_x_tol=1.5,
                line_id_start=line_id,
                line_sep_override="",
            )
            out_parts.append(cell_text)
            out_chars.extend(cell_chars)
            _append_token(out_chars, out_parts, "\n", None, line_id)
            line_id += 1

    return ("".join(out_parts), out_chars, line_id)


def extract_text_indexed(pdf_bytes: bytes) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        full_parts: list[str] = []
        full_chars: list[dict] = []
        pages_out: list[dict] = []

        offset = 0
        global_line_id = 0

        for pidx, page in enumerate(doc):
            page_parts: list[str] = []
            page_chars: list[dict] = []

            table_bboxes: list[fitz.Rect] = []
            segments: list[tuple[float, str, list]] = []

            try:
                finder = page.find_tables()
                tables = getattr(finder, "tables", None) or []
            except Exception:
                tables = []

            dbg_on = _pdf_extract_debug_enabled()
            if dbg_on and tables:
                logger.info("%s tables_detected page=%d count=%d", log_prefix, pidx + 1, len(tables))

            for tab in tables:
                try:
                    bbox = fitz.Rect(getattr(tab, "bbox"))
                except Exception:
                    continue
                table_bboxes.append(bbox)
                seg_text, seg_chars, next_line = _table_to_text_and_chars(page, tab, line_id_start=global_line_id)
                global_line_id = next_line
                y0 = float(bbox.y0)
                if seg_text.strip():
                    if dbg_on:
                        # 표 텍스트는 셀/줄 경계로 인해 단어가 분리되기 쉬우므로,
                        # 공백/개행이 보이도록 스니펫 로그를 남긴다.
                        snip = seg_text[:400]
                        logger.info("%s table_text_snip page=%d:\n%s", log_prefix, pidx + 1, _vis_ws(snip))
                    segments.append((y0, seg_text, seg_chars))

            words_all = page.get_text("words") or []
            words_nt = []
            if table_bboxes:
                for w in words_all:
                    try:
                        x0, y0, x1, y1 = float(w[0]), float(w[1]), float(w[2]), float(w[3])
                    except Exception:
                        continue
                    cx = (x0 + x1) / 2.0
                    cy = (y0 + y1) / 2.0
                    inside = False
                    for tb in table_bboxes:
                        if tb.contains(fitz.Point(cx, cy)):
                            inside = True
                            break
                    if not inside:
                        words_nt.append(w)
            else:
                words_nt = words_all

            nt_lines = _group_words_to_lines(words_nt, y_tol=2.0)
            nt_text, nt_chars, next_line = _words_lines_to_text_and_chars(
                nt_lines,
                join_lines_with_space=False,
                gap_x_tol=1.5,
                line_id_start=global_line_id,
            )
            global_line_id = next_line
            if nt_text.strip():
                first_y0 = 0.0
                if words_nt:
                    try:
                        first_y0 = float(sorted(words_nt, key=lambda w: (w[1], w[0]))[0][1])
                    except Exception:
                        first_y0 = 0.0
                segments.append((first_y0, nt_text, nt_chars))

            segments.sort(key=lambda t: t[0])

            for _si, (_y0, seg_text, seg_chars) in enumerate(segments):
                if not seg_text:
                    continue
                if page_parts:
                    _append_token(page_chars, page_parts, "\n\n", None, global_line_id)
                    global_line_id += 2
                page_parts.append(seg_text)
                page_chars.extend(seg_chars)

            page_text = "".join(page_parts).strip()

            if page_text:
                start = offset
                full_parts.append(page_text)
                for ch in page_chars:
                    full_chars.append({"page": pidx, **ch})
                offset += len(page_text)

                pages_out.append({"page": pidx + 1, "text": page_text, "start": start, "end": offset})

                full_parts.append("\n\n")
                full_chars.extend([{"page": pidx, "bbox": None, "line_id": global_line_id} for _ in "\n\n"])
                offset += 2
                global_line_id += 2

        full_text = "".join(full_parts).rstrip()
        if len(full_chars) > len(full_text):
            full_chars = full_chars[: len(full_text)]

        return {"full_text": full_text, "pages": pages_out, "char_index": full_chars}
    finally:
        doc.close()


def _boxes_from_index_span(index: dict, start: int, end: int) -> List[Box]:
    chars = index.get("char_index") or []
    if not chars:
        return []

    s = max(0, int(start))
    e = min(len(chars), int(end))
    if e <= s:
        return []

    boxes: dict[tuple, int] = {}
    for i in range(s, e):
        ch = chars[i]
        bbox = ch.get("bbox")
        page = ch.get("page")
        if bbox is None or page is None:
            continue
        key = (int(page), float(bbox[0]), float(bbox[1]), float(bbox[2]), float(bbox[3]))
        boxes[key] = 1

    out: List[Box] = []
    for (p, x0, y0, x1, y1) in boxes.keys():
        out.append(Box(page=p, x0=x0, y0=y0, x1=x1, y1=y1))
    return out


def extract_markdown(pdf_bytes: bytes) -> dict:
    if pymupdf4llm is None:
        return {"ok": False, "markdown": ""}

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            md = pymupdf4llm.to_markdown(doc)
            return {"ok": True, "markdown": md}
        finally:
            doc.close()
    except Exception:
        pass

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as f:
        f.write(pdf_bytes)
        f.flush()
        md = pymupdf4llm.to_markdown(f.name)
        return {"ok": True, "markdown": md}


def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem]) -> List[Box]:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    try:
        for pidx, page in enumerate(doc):
            text = page.get_text("text") or ""
            text = cleanup_text(text)

            found = match_text(text)
            items = found.get("items", []) or []
            for it in items:
                if it.get("valid") is False:
                    continue
                val = it.get("value") or ""
                val = _compact_ws(str(val))
                if not val:
                    continue
                rects = _search_with_whitespace_fallback(page, val)
                for r in rects:
                    boxes.append(Box(page=pidx, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
    finally:
        doc.close()

    return boxes


def apply_redaction(pdf_bytes: bytes, boxes: List[Box]) -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        touched: set[int] = set()

        for b in boxes:
            if b.page < 0 or b.page >= len(doc):
                continue
            page = doc[b.page]
            rect = fitz.Rect(b.x0, b.y0, b.x1, b.y1)
            page.add_redact_annot(rect, fill=(0, 0, 0))
            touched.add(int(b.page))

        for pno in sorted(touched):
            doc[pno].apply_redactions()

        return doc.tobytes()
    finally:
        doc.close()


def _search_with_whitespace_fallback(page: fitz.Page, needle: str) -> List[fitz.Rect]:
    rects = page.search_for(needle) or []
    if rects:
        return rects

    n2 = _compact_ws(needle)
    if n2 and n2 != needle:
        rects = page.search_for(n2) or []
        if rects:
            return rects

    n3 = needle.replace("\n", " ").replace("\r", " ")
    n3 = _compact_ws(n3)
    if n3 and n3 not in (needle, n2):
        rects = page.search_for(n3) or []
        if rects:
            return rects

    return []


def apply_text_redaction(pdf_bytes: bytes, extra_spans: list | None = None) -> bytes:
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    index = None
    try:
        index = extract_text_indexed(pdf_bytes)
    except Exception:
        index = None

    if extra_spans and index and index.get("char_index"):
        for sp in extra_spans:
            s = sp.get("start")
            e = sp.get("end")
            try:
                s_i = int(s)
                e_i = int(e)
            except Exception:
                continue
            if e_i <= s_i:
                continue
            boxes.extend(_boxes_from_index_span(index, s_i, e_i))

        return apply_redaction(pdf_bytes, boxes)

    def _strip_md_noise(s: str) -> str:
        if not s:
            return ""
        s = s.replace("\u00a0", " ")
        s = re.sub(r"[`*_>#|]", " ", s)
        return s.strip()

    if extra_spans:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            for span in extra_spans:
                raw_text = span.get("text", "")
                span_text = _strip_md_noise(_compact_ws(raw_text))
                if not span_text:
                    continue

                p0 = span.get("page")
                page_order = list(range(len(doc)))
                if isinstance(p0, int) and 0 <= p0 < len(doc):
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
    try:
        out = []
        for pidx, page in enumerate(doc):
            try:
                finder = page.find_tables()
                tables = getattr(finder, "tables", None) or []
            except Exception:
                tables = []
            for t in tables:
                try:
                    bbox = list(getattr(t, "bbox"))
                except Exception:
                    bbox = None
                out.append(
                    {
                        "page": pidx + 1,
                        "bbox": bbox,
                        "row_count": getattr(t, "row_count", None),
                        "col_count": getattr(t, "col_count", None),
                    }
                )
        return {"tables": out}
    finally:
        doc.close()
