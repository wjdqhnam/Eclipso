from __future__ import annotations

import io
import re
from typing import List, Optional, Set, Dict

import fitz
import numpy as np

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS
from .common import cleanup_text, compile_rules
from .ocr_module import run_paddle_ocr, OcrItem

log_prefix = "[PDF]"


# ─────────────────────────────────────────────────────────────
# /text/extract 용 텍스트 추출
# ─────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────
# 헬퍼들
# ─────────────────────────────────────────────────────────────
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
            return bool(validator(value, None))
    except Exception:
        print(f"{log_prefix} VALIDATOR ERROR", repr(value))
        return False


def _merge_card_rects(rects: List[fitz.Rect]) -> List[fitz.Rect]:
    if len(rects) <= 1:
        return rects

    rects_sorted = sorted(rects, key=lambda r: (r.y0, r.x0))

    line_clusters: List[List[fitz.Rect]] = []
    current_cluster: List[fitz.Rect] = [rects_sorted[0]]

    Y_TOL = 2.0

    for r in rects_sorted[1:]:
        last = current_cluster[-1]
        if abs(r.y0 - last.y0) <= Y_TOL:
            current_cluster.append(r)
        else:
            line_clusters.append(current_cluster)
            current_cluster = [r]
    line_clusters.append(current_cluster)

    merged: List[fitz.Rect] = []

    for cluster in line_clusters:
        if len(cluster) == 1:
            merged.append(cluster[0])
        else:
            x0 = min(r.x0 for r in cluster)
            y0 = min(r.y0 for r in cluster)
            x1 = max(r.x1 for r in cluster)
            y1 = max(r.y1 for r in cluster)
            merged.append(fitz.Rect(x0, y0, x1, y1))

    return merged


# ─────────────────────────────────────────────────────────────
# 이미지/OCR 헬퍼
# ─────────────────────────────────────────────────────────────
def _page_to_image_rgb(page: fitz.Page, zoom: float = 2.0) -> tuple[np.ndarray, float, float]:
    mat = fitz.Matrix(zoom, zoom)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    img_w, img_h = pix.width, pix.height
    img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(img_h, img_w, 3)
    return img, float(img_w), float(img_h)


def ocr_boxes_for_page(
    doc: fitz.Document,
    page_index: int,
    patterns: List[PatternItem] | None = None,
    min_score: float = 0.5,
    stats_ok: Dict[str, int] | None = None,
    stats_fail: Dict[str, int] | None = None,
) -> List[Box]:
    page = doc.load_page(page_index)
    page_rect = page.rect
    page_w, page_h = page_rect.width, page_rect.height

    img, img_w, img_h = _page_to_image_rgb(page)
    print(f"{log_prefix} [OCR] page={page_index + 1} image={img_w}x{img_h}")

    ocr_items: List[OcrItem] = run_paddle_ocr(img, min_score=min_score)
    print(f"{log_prefix} [OCR] page={page_index + 1} ocr_items={len(ocr_items)}")

    comp = compile_rules()
    allowed_names = _normalize_pattern_names(patterns)

    boxes: List[Box] = []

    for item in ocr_items:
        print(f"{log_prefix} [OCR RAW] page={page_index + 1} text={repr(item.text)} score={item.score}")
        text = cleanup_text(item.text)
        if not text:
            continue

        matched = False

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

                if stats_ok is not None and stats_fail is not None:
                    if ok:
                        stats_ok[rule_name] = stats_ok.get(rule_name, 0) + 1
                    else:
                        stats_fail[rule_name] = stats_fail.get(rule_name, 0) + 1

                print(
                    f"{log_prefix} MATCH(OCR)",
                    "page=", page_index + 1,
                    "rule=", rule_name,
                    "need_valid=", need_valid,
                    "ok=", ok,
                    "value=", repr(val),
                )

                if not ok:
                    continue

                x0_img, y0_img, x1_img, y1_img = item.bbox

                x0_pdf = x0_img / img_w * page_w
                x1_pdf = x1_img / img_w * page_w
                y0_pdf = y0_img / img_h * page_h
                y1_pdf = y1_img / img_h * page_h

                boxes.append(
                    Box(
                        page=page_index,
                        x0=float(x0_pdf),
                        y0=float(y0_pdf),
                        x1=float(x1_pdf),
                        y1=float(y1_pdf),
                    )
                )
                matched = True

        if (not matched) and (not allowed_names or "email" in allowed_names) and "@" in text:
            x0_img, y0_img, x1_img, y1_img = item.bbox

            x0_pdf = x0_img / img_w * page_w
            x1_pdf = x1_img / img_w * page_w
            y0_pdf = y0_img / img_h * page_h
            y1_pdf = y1_img / img_h * page_h

            boxes.append(
                Box(
                    page=page_index,
                    x0=float(x0_pdf),
                    y0=float(y0_pdf),
                    x1=float(x1_pdf),
                    y1=float(y1_pdf),
                )
            )

    print(f"{log_prefix} [OCR] page={page_index + 1} boxes_from_ocr={len(boxes)}")
    return boxes


# ─────────────────────────────────────────────────────────────
# PDF 내 박스 탐지
# ─────────────────────────────────────────────────────────────
def detect_boxes_from_patterns(
    pdf_bytes: bytes,
    patterns: List[PatternItem] | None,
    use_ocr: bool = True,
) -> List[Box]:
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
        page_count = len(doc)
        for pno in range(page_count):
            page = doc.load_page(pno)
            raw_text = page.get_text("text") or ""
            text = cleanup_text(raw_text)
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
                        "page=", pno + 1,
                        "rule=", rule_name,
                        "need_valid=", need_valid,
                        "ok=", ok,
                        "value=", repr(val),
                    )
                    if not ok:
                        continue
                    rects = list(page.search_for(val))
                    if not rects:
                        continue

                    if rule_name == "card" and "-" not in val and len(rects) > 1:
                        rects = _merge_card_rects(rects)

                    if ok and rule_name == "card":
                        digits = re.sub(r"\D", "", val)
                        if len(digits) >= 4:
                            suffix = digits[-4:]
                            extra_rects = list(page.search_for(suffix))
                            for r in extra_rects:
                                rects.append(r)

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

        if use_ocr:
            for pno in range(page_count):
                ocr_bs = ocr_boxes_for_page(doc, pno, patterns, stats_ok=stats_ok, stats_fail=stats_fail)
                for b in ocr_bs:
                    print(
                        f"{log_prefix}[OCR] BOX",
                        "page=", pno + 1,
                        "rect=", (b.x0, b.y0, b.x1, b.y1),
                    )
                boxes.extend(ocr_bs)

    finally:
        doc.close()

    print(
        f"{log_prefix} detect summary",
        "OK=", {k: v for k, v in sorted(stats_ok.items())},
        "FAIL=", {k: v for k, v in sorted(stats_fail.items())},
        "boxes=", len(boxes),
    )

    return boxes


# ─────────────────────────────────────────────────────────────
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
