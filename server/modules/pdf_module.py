from __future__ import annotations

import io
import os
import re
import logging
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

import fitz

try:
    import pymupdf4llm  # type: ignore
except Exception:
    pymupdf4llm = None  # type: ignore

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS
from server.core.regex_utils import match_text

try:
    from server.modules.common import cleanup_text
except Exception:  # pragma: no cover
    from ..modules.common import cleanup_text  # type: ignore

# Optional OCR deps
try:
    from server.modules.ocr_module import easyocr_blocks  # type: ignore
except Exception:
    easyocr_blocks = None  # type: ignore

try:
    from server.modules.ocr_qwen_post import classify_blocks_with_qwen  # type: ignore
except Exception:
    classify_blocks_with_qwen = None  # type: ignore

try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None  # type: ignore


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


# (/text/extract)
def extract_text(file_bytes: bytes) -> dict:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    try:
        pages: List[dict] = []
        all_chunks: List[str] = []
        for idx, page in enumerate(doc):
            raw = page.get_text("text") or ""
            cleaned = raw.replace("\r", "")
            pages.append({"page": idx + 1, "text": cleaned})
            all_chunks.append(cleaned)
        full_text = "\n\n".join(all_chunks).strip()
        return {"full_text": full_text, "pages": pages}
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
    cur_y: Optional[float] = None
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
            sep = line_sep_override if line_sep_override is not None else (" " if join_lines_with_space else "\n")
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

    uniq: dict[tuple, int] = {}
    for i in range(s, e):
        ch = chars[i]
        bbox = ch.get("bbox")
        page = ch.get("page")
        if bbox is None or page is None:
            continue
        key = (int(page), float(bbox[0]), float(bbox[1]), float(bbox[2]), float(bbox[3]))
        uniq[key] = 1

    out: List[Box] = []
    for (p, x0, y0, x1, y1) in uniq.keys():
        out.append(Box(page=p, x0=x0, y0=y0, x1=x1, y1=y1))
    return out


# (/text/markdown)
def extract_markdown(pdf_bytes: bytes, by_page: bool = True) -> dict:
    if pymupdf4llm is None:
        return {"ok": False, "markdown": "", "pages": []}

    # 1) in-memory doc 방식
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            if by_page:
                chunks = pymupdf4llm.to_markdown(doc, tables=True, page_chunks=True, show_progress=False)
                pages = []
                full_md = []
                for i, chunk in enumerate(chunks):
                    if isinstance(chunk, dict):
                        md_text = chunk.get("markdown") or chunk.get("text") or ""
                    else:
                        md_text = str(chunk)
                    pages.append({"page": i + 1, "markdown": md_text})
                    full_md.append(md_text)
                return {"ok": True, "markdown": "\n\n".join(full_md), "pages": pages}
            md = pymupdf4llm.to_markdown(doc, tables=True, show_progress=False)
            return {"ok": True, "markdown": str(md), "pages": []}
        finally:
            doc.close()
    except Exception as e:
        logger.error("%s PDF to Markdown error(in-memory): %s", log_prefix, e)

    # 2) fallback: 임시 파일 방식
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(pdf_bytes)
            tmp_name = f.name

        try:
            chunks = pymupdf4llm.to_markdown(tmp_name, tables=True, page_chunks=True, show_progress=False)
            pages = []
            full_md = []
            for i, chunk in enumerate(chunks):
                if isinstance(chunk, dict):
                    md_text = chunk.get("markdown") or chunk.get("text") or ""
                else:
                    md_text = str(chunk)
                pages.append({"page": i + 1, "markdown": md_text})
                full_md.append(md_text)
            return {"ok": True, "markdown": "\n\n".join(full_md), "pages": pages}
        finally:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)
    except Exception as e:
        return {"ok": False, "markdown": "", "pages": [], "error": str(e)}


def _normalize_pattern_names(patterns: Optional[List[PatternItem]]) -> Optional[Set[str]]:
    if not patterns:
        return None
    names: Set[str] = set()
    for p in patterns:
        nm = getattr(p, "name", None) or getattr(p, "rule", None)
        if nm:
            names.add(str(nm).lower())
    return names or None


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


def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: Optional[List[PatternItem]] = None) -> List[Box]:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []
    allowed = _normalize_pattern_names(patterns)

    try:
        for pidx, page in enumerate(doc):
            text = cleanup_text(page.get_text("text") or "")
            found = match_text(text)  # {'items': [...], 'counts': {...}}

            items = found.get("items", []) or []
            for it in items:
                if it.get("valid") is False:
                    continue

                rule = (it.get("rule") or it.get("name") or "").lower()
                if allowed is not None and rule not in allowed:
                    continue

                val = _compact_ws(str(it.get("value") or ""))
                if not val:
                    continue

                rects = _search_with_whitespace_fallback(page, val)
                for r in rects:
                    boxes.append(Box(page=pidx, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
    finally:
        doc.close()

    return boxes

# OCR -> Boxes (optional)
def _page_to_pil(page: fitz.Page, dpi: int = 120):
    if Image is None:
        return None
    mat = fitz.Matrix(dpi / 72, dpi / 72)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    return Image.frombytes("RGB", (pix.width, pix.height), pix.samples)


def detect_boxes_from_ocr(
    pdf_bytes: bytes,
    *,
    dpi: int = 120,
    use_llm: bool = True,
    min_conf: float = 0.3,
) -> List[Box]:
    if easyocr_blocks is None or Image is None:
        return []

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    scale = dpi / 72.0
    inv_scale = 1.0 / scale

    try:
        for pno, page in enumerate(doc):
            img = _page_to_pil(page, dpi=dpi)
            if img is None:
                continue

            ocr_blocks = easyocr_blocks(img, min_conf=min_conf, gpu=False) or []

            if use_llm and classify_blocks_with_qwen is not None and ocr_blocks:
                try:
                    ocr_blocks = classify_blocks_with_qwen(ocr_blocks) or ocr_blocks
                except Exception:
                    pass

            for blk in ocr_blocks:
                kind = blk.get("kind") or "none"
                if use_llm and kind == "none":
                    continue

                x0_px, y0_px, x1_px, y1_px = blk.get("bbox") or [0, 0, 0, 0]

                x0 = float(x0_px) * inv_scale
                y0 = float(y0_px) * inv_scale
                x1 = float(x1_px) * inv_scale
                y1 = float(y1_px) * inv_scale

                rect_pdf = fitz.Rect(x0, y0, x1, y1) & page.rect
                boxes.append(Box(page=pno, x0=rect_pdf.x0, y0=rect_pdf.y0, x1=rect_pdf.x1, y1=rect_pdf.y1))
    finally:
        doc.close()

    return boxes



def _fill_color(fill: str):
    f = (fill or "black").strip().lower()
    if f == "white":
        return (1, 1, 1)
    return (0, 0, 0)


def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        touched: set[int] = set()
        fcol = _fill_color(fill)

        for b in boxes:
            if b.page < 0 or b.page >= len(doc):
                continue
            page = doc[b.page]
            rect = fitz.Rect(b.x0, b.y0, b.x1, b.y1)
            page.add_redact_annot(rect, fill=fcol)
            touched.add(int(b.page))

        for pno in sorted(touched):
            doc[pno].apply_redactions()

        return doc.tobytes()
    finally:
        doc.close()


def apply_text_redaction(
    pdf_bytes: bytes,
    extra_spans: Optional[List[dict]] = None,
    *,
    fill: str = "black",
    use_ocr: bool = False,
    use_llm: bool = True,
    dpi: int = 120,
    min_conf: float = 0.3,
) -> bytes:
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    if use_ocr:
        boxes.extend(detect_boxes_from_ocr(pdf_bytes, dpi=dpi, use_llm=use_llm, min_conf=min_conf))

    # NER span(start/end) 기반이면 indexed로 box 변환(가장 안정적)
    if extra_spans:
        try:
            index = extract_text_indexed(pdf_bytes)
        except Exception:
            index = None

        if index and index.get("char_index"):
            for sp in extra_spans:
                try:
                    s_i = int(sp.get("start"))
                    e_i = int(sp.get("end"))
                except Exception:
                    continue
                if e_i <= s_i:
                    continue
                boxes.extend(_boxes_from_index_span(index, s_i, e_i))

    return apply_redaction(pdf_bytes, boxes, fill=fill)


# Table layout (/redactions/tables)
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
