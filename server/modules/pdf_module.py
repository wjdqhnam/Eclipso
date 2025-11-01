import io, fitz, logging, re
from typing import List
from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules.ner_module import run_ner
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY
from server.core.regex_utils import match_text

log = logging.getLogger("pdf_redact")

def _compiled_regex(pat: PatternItem) -> re.Pattern:
    try:
        rp = getattr(pat, "compiled", None)
        if rp is not None:
            return rp
        return re.compile(pat.regex)
    except Exception as e:
        name = getattr(pat, "name", "UNKNOWN")
        raise ValueError(f"regex compile failed: {name}: {e}")

def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem]) -> List[Box]:
    boxes: List[Box] = []
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        for pno, page in enumerate(doc):
            text = page.get_text("text") or ""
            for pattern in patterns:
                rp = _compiled_regex(pattern)
                for m in rp.finditer(text):
                    frag = m.group(0)
                    if not frag:
                        continue
                    rects = page.search_for(frag)
                    for r in rects:
                        boxes.append(Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
    finally:
        doc.close()
    return boxes

def _fill_color(fill: str):
    f = (fill or "black").strip().lower()
    return (0, 0, 0) if f == "black" else (1, 1, 1)

def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill="black") -> bytes:
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
