from __future__ import annotations

import io
import re
from typing import List, Optional, Set, Dict, Any

import fitz  # PyMuPDF
import pymupdf4llm
import logging

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules.ner_module import run_ner
from server.core.regex_utils import match_text

from server.modules.ocr_module import easyocr_blocks
from server.modules.ocr_qwen_post import classify_blocks_with_qwen
from PIL import Image


log_prefix = "[PDF]"
logger = logging.getLogger(__name__)


def extract_text(file_bytes: bytes) -> dict:
    # PDF 텍스트 레이어를 page별/전체로 추출 (/text/extract)
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    try:
        pages = []
        all_chunks: List[str] = []

        for idx, page in enumerate(doc):
            raw = page.get_text("text") or ""
            cleaned = raw.replace("\r", "")
            pages.append({"page": idx + 1, "text": cleaned})
            if cleaned:
                all_chunks.append(cleaned)

        full_text = "\n\n".join(all_chunks)

        return {"full_text": full_text, "pages": pages}
    finally:
        doc.close()


def extract_table_layout(pdf_bytes: bytes) -> dict:
    # PyMuPDF table finder로 표 bbox/행/열 개수만 수집
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    tables: List[dict] = []

    try:
        for page_idx, page in enumerate(doc):
            finder = page.find_tables()
            if not finder or not finder.tables:
                continue

            for t in finder.tables:
                rect = fitz.Rect(t.bbox)
                tables.append(
                    {
                        "page": page_idx + 1,
                        "bbox": [rect.x0, rect.y0, rect.x1, rect.y1],
                        "row_count": t.row_count,
                        "col_count": t.col_count,
                    }
                )
    finally:
        doc.close()

    return {"tables": tables}


def extract_markdown(pdf_bytes: bytes, by_page: bool = True) -> dict:
    # pymupdf4llm 기반 마크다운 추출 (/text/markdown)
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        if by_page:
            chunks = pymupdf4llm.to_markdown(doc=doc, page_chunks=True)
            pages: List[dict] = []

            for idx, ch in enumerate(chunks, start=1):
                meta = ch.get("metadata", {}) or {}
                page_no = meta.get("page_number") or idx

                md = (ch.get("text") or "").replace("<br>", "")
                raw_tables = ch.get("tables", []) or []
                tables: List[dict] = []

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

                pages.append({"page": page_no, "markdown": md, "tables": tables})

            full_md = "\n\n".join(p["markdown"] for p in pages if p["markdown"])
            return {"markdown": full_md, "pages": pages}

        md = pymupdf4llm.to_markdown(doc=doc).replace("<br>", "\n")
        return {"markdown": md, "pages": []}
    finally:
        doc.close()


def _normalize_pattern_names(patterns: List[PatternItem] | None) -> Optional[Set[str]]:
    # 입력 패턴 목록에서 허용 rule name set 생성
    if not patterns:
        return None
    names: Set[str] = set()
    for p in patterns:
        nm = getattr(p, "name", None) or getattr(p, "rule", None)
        if nm:
            names.add(nm)
    return names or None


def _is_valid_value(need_valid: bool, validator, value: str) -> bool:
    # validator(있으면)로 값 검증
    if not need_valid or not callable(validator):
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            return bool(validator(value, None))
    except Exception:
        print(f"{log_prefix} VALIDATOR ERROR", repr(value))
        return False


def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem] | None) -> List[Box]:
    # 텍스트 레이어에서 정규식 매치 → search_for로 좌표(box) 생성
    from server.modules.common import compile_rules  # lazy import

    comp = compile_rules()
    allowed_names = _normalize_pattern_names(patterns)

    print(
        f"{log_prefix} detect_boxes_from_patterns: rules 준비 완료",
        "allowed_names=",
        sorted(allowed_names) if allowed_names else "ALL",
    )

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

                    if not ok:
                        continue

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
                        boxes.append(Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
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


def _page_to_pil(page: fitz.Page, dpi: int = 120) -> Image.Image:
    # PDF 페이지를 raster 이미지(PIL)로 렌더링 (OCR용)
    mat = fitz.Matrix(dpi / 72, dpi / 72)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    return Image.frombytes("RGB", (pix.width, pix.height), pix.samples)


def _group_rows_by_y(blocks: List[Dict[str, Any]], row_tol: float = 35.0) -> List[List[Dict[str, Any]]]:
    # OCR 블록을 y-center 기준으로 행(row) 클러스터링
    if not blocks:
        return []

    enriched: List[Dict[str, Any]] = []
    for b in blocks:
        x0, y0, x1, y1 = b.get("bbox", [0, 0, 0, 0])
        cy = 0.5 * (float(y0) + float(y1))
        bb = dict(b)
        bb["_cy"] = cy
        enriched.append(bb)

    enriched.sort(key=lambda b: b["_cy"])

    rows: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    last_cy: Optional[float] = None

    for b in enriched:
        cy = b["_cy"]
        if last_cy is None or abs(cy - last_cy) <= row_tol:
            current.append(b)
        else:
            rows.append(current)
            current = [b]
        last_cy = cy

    if current:
        rows.append(current)

    for row in rows:
        for b in row:
            b.pop("_cy", None)

    for row in rows:
        row.sort(key=lambda b: float((b.get("bbox") or [0, 0, 0, 0])[0]))

    return rows


def _text_for_post(b: Dict[str, Any]) -> str:
    # LLM 후처리 결과(normalized) 우선 사용
    return str(b.get("normalized") or b.get("text") or "").strip()


def _count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)


def _looks_value_like(s: str) -> bool:
    # 라벨이 아닌 "값"처럼 보이는 토큰을 판별(라벨 전체 마스킹 방지용)
    if not s:
        return False
    if "@" in s:
        return True
    d = _count_digits(s)
    if d >= 2:
        return True
    if "-" in s or "." in s:
        return d >= 1
    if 2 <= len(s) <= 4 and s.isalpha():
        return True
    return False


def _is_incomplete_sensitive(kind: str, text: str) -> bool:
    # 끊긴 값(멀티라인) 후보 판별(card/email만)
    t = text.strip()
    if not t:
        return False

    if kind == "card":
        digits = _count_digits(t)
        return 10 <= digits <= 15
    if kind == "email":
        if "@" not in t:
            return False
        return t.endswith(".") or (re.search(r"\.[A-Za-z]{2,4}$", t) is None)
    return False


def _promote_value_like_in_rows(blocks: List[Dict[str, Any]]) -> None:
    # 같은 행에서 "값처럼 보이는 토큰"만 민감값으로 승격
    SENSITIVE = {"card", "phone", "email", "id"}

    rows = _group_rows_by_y(blocks, row_tol=35.0)
    for row in rows:
        sens = [b for b in row if (b.get("kind") in SENSITIVE)]
        if not sens:
            continue

        sens_min_x0 = min(float((b.get("bbox") or [0, 0, 0, 0])[0]) for b in sens)

        for b in row:
            if (b.get("kind") in (None, "", "none")):
                t = _text_for_post(b)
                if not _looks_value_like(t):
                    continue

                x0 = float((b.get("bbox") or [0, 0, 0, 0])[0])
                if x0 + 3.0 < sens_min_x0:
                    continue

                b["kind"] = sens[0].get("kind") or "row_sensitive"


def _promote_multiline_continuations(blocks: List[Dict[str, Any]]) -> None:
    # 끊긴 값(다음 줄 파편)을 같은 kind로 전파
    rows = _group_rows_by_y(blocks, row_tol=35.0)
    if len(rows) < 2:
        return

    def x_overlap_ratio(a: List[float], b: List[float]) -> float:
        ax0, _, ax1, _ = a
        bx0, _, bx1, _ = b
        inter = max(0.0, min(ax1, bx1) - max(ax0, bx0))
        denom = max(1.0, min(ax1 - ax0, bx1 - bx0))
        return inter / denom

    for i in range(len(rows) - 1):
        cur = rows[i]
        nxt = rows[i + 1]

        for a in cur:
            kind = a.get("kind") or "none"
            if kind not in ("card", "email"):
                continue

            at = _text_for_post(a)
            if not _is_incomplete_sensitive(kind, at):
                continue

            ab = list(map(float, (a.get("bbox") or [0, 0, 0, 0])))
            ax0, ay0, ax1, ay1 = ab
            acx = 0.5 * (ax0 + ax1)

            best = None
            best_score = 0.0

            for b in nxt:
                if (b.get("kind") or "none") != "none":
                    continue

                bt = _text_for_post(b)
                if not bt:
                    continue

                bb = list(map(float, (b.get("bbox") or [0, 0, 0, 0])))
                bx0, by0, bx1, by1 = bb
                bcx = 0.5 * (bx0 + bx1)

                if by0 - ay1 > 40.0:
                    continue

                ov = x_overlap_ratio(ab, bb)
                if ov < 0.25 and abs(bcx - acx) > 80.0:
                    continue

                if kind == "card":
                    if not bt.replace("-", "").replace(" ", "").isdigit():
                        continue
                    if _count_digits(bt) > 6:
                        continue
                else:
                    if not (2 <= len(bt) <= 6 and bt.isalpha()):
                        continue

                score = ov - (abs(bcx - acx) / 1000.0)
                if score > best_score:
                    best_score = score
                    best = b

            if best is not None:
                best["kind"] = kind


def detect_boxes_from_ocr(
    pdf_bytes: bytes,
    *,
    dpi: int = 120,
    use_llm: bool = True,
    min_conf: float = 0.3,
) -> List[Box]:
    # 페이지 raster→OCR→(옵션)LLM kind→PDF좌표 변환→텍스트레이어 겹침 제외
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    scale = dpi / 72.0
    inv_scale = 1.0 / scale

    try:
        for pno, page in enumerate(doc):
            words = page.get_text("words") or []
            text_rects = [fitz.Rect(w[0], w[1], w[2], w[3]) for w in words]

            def overlaps_text_layer(r: fitz.Rect) -> bool:
                for tr in text_rects:
                    if not r.intersects(tr):
                        continue
                    inter = r & tr
                    if inter.get_area() > 0:
                        return True
                return False

            img = _page_to_pil(page, dpi=dpi)

            ocr_blocks = easyocr_blocks(img, min_conf=min_conf, gpu=False)
            print(f"{log_prefix} OCR page={pno + 1} blocks=", len(ocr_blocks))

            if use_llm and ocr_blocks:
                ocr_blocks = classify_blocks_with_qwen(ocr_blocks)
                _promote_value_like_in_rows(ocr_blocks)
                _promote_multiline_continuations(ocr_blocks)

            for blk in ocr_blocks:
                kind = blk.get("kind") or "none"
                if use_llm and kind == "none":
                    continue

                x0_px, y0_px, x1_px, y1_px = blk["bbox"]

                x0 = float(x0_px) * inv_scale
                y0 = float(y0_px) * inv_scale
                x1 = float(x1_px) * inv_scale
                y1 = float(y1_px) * inv_scale

                width = x1 - x0
                height = y1 - y0

                if height > 1.0:
                    pad_y = min(max(height * 0.15, 0.6), 3.0)
                    y0 -= pad_y
                    y1 += pad_y

                if width > 1.0:
                    pad_x_left = min(max(width * 0.01, 0.2), 1.2)
                    pad_x_right = min(max(width * 0.06, 0.8), 6.0)
                    x0 -= pad_x_left
                    x1 += pad_x_right

                rect_pdf = fitz.Rect(x0, y0, x1, y1) & page.rect
                if overlaps_text_layer(rect_pdf):
                    continue

                print(
                    f"{log_prefix} OCR BOX",
                    "page=",
                    pno + 1,
                    "kind=",
                    kind,
                    "text=",
                    repr(_text_for_post(blk)),
                    "bbox_px=",
                    (x0_px, y0_px, x1_px, y1_px),
                    "bbox_pdf=",
                    (rect_pdf.x0, rect_pdf.y0, rect_pdf.x1, rect_pdf.y1),
                )

                boxes.append(
                    Box(
                        page=pno,
                        x0=rect_pdf.x0,
                        y0=rect_pdf.y0,
                        x1=rect_pdf.x1,
                        y1=rect_pdf.y1,
                    )
                )
    finally:
        doc.close()

    print(f"{log_prefix} detect_boxes_from_ocr summary", "boxes=", len(boxes))
    return boxes


def _fill_color(fill: str):
    # PyMuPDF fill 색상(0~1 float) 변환
    f = (fill or "black").strip().lower()
    return (0, 0, 0) if f == "black" else (1, 1, 1)


def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
    # Box 리스트를 실제 redact annotation으로 적용 후 저장
    print(f"{log_prefix} apply_redaction: boxes=", len(boxes), "fill=", fill)
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


def apply_text_redaction(pdf_bytes: bytes, extra_spans: List[dict] | None = None) -> bytes:
    # 패턴 탐지 + OCR 탐지 + (옵션) NER span을 박스로 변환 후 일괄 레닥션
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    ocr_boxes = detect_boxes_from_ocr(pdf_bytes, dpi=120, use_llm=True, min_conf=0.3)

    print(
        f"{log_prefix} apply_text_redaction: pattern_boxes=",
        len(boxes),
        "ocr_boxes=",
        len(ocr_boxes),
    )

    boxes.extend(ocr_boxes)

    if extra_spans:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            page_texts: List[str] = []
            page_offsets: List[int] = []
            current_offset = 0

            for page in doc:
                text = page.get_text("text") or ""
                page_texts.append(text)
                page_offsets.append(current_offset)
                current_offset += len(text) + 1

            full_text = "\n".join(page_texts)

            for span in extra_spans:
                start = span.get("start", 0)
                end = span.get("end", 0)
                if end <= start or start >= len(full_text):
                    continue

                span_text = full_text[start: min(end, len(full_text))]
                if not span_text or not span_text.strip():
                    continue

                search_text = span_text.strip()
                if not search_text:
                    continue

                for page_idx, page_offset in enumerate(page_offsets):
                    next_offset = page_offsets[page_idx + 1] if page_idx + 1 < len(page_offsets) else len(full_text)
                    if start >= page_offset and start < next_offset:
                        page = doc[page_idx]
                        rects = page.search_for(search_text)

                        if rects:
                            for r in rects:
                                boxes.append(Box(page=page_idx, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))

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
