import re
import io
import fitz  # PyMuPDF
import logging
from typing import List, Tuple, Optional
from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS, RULES

logger = logging.getLogger("pdf_redact")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)


# ---------------------------------------------------------
# 내부 유틸: 정규식 기반 탐지
# ---------------------------------------------------------
def _compile_pattern(p: PatternItem) -> re.Pattern:
    flags = 0 if p.case_sensitive else re.IGNORECASE
    pattern = p.regex
    if p.whole_word:
        pattern = rf"\b(?:{pattern})\b"
    return re.compile(pattern, flags)


def _word_spans_to_rect(words: List[tuple], spans: List[Tuple[int, int]]) -> List[fitz.Rect]:
    rects: List[fitz.Rect] = []
    for s, e in spans:
        chunk = words[s:e]
        if not chunk:
            continue
        x0 = min(w[0] for w in chunk)
        y0 = min(w[1] for w in chunk)
        x1 = max(w[2] for w in chunk)
        y1 = max(w[3] for w in chunk)
        rects.append(fitz.Rect(x0, y0, x1, y1))
    return rects


# ---------------------------------------------------------
# 1) PDF 내부 패턴 탐지 (텍스트 영역별 Box 추출)
# ---------------------------------------------------------
def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem]) -> List[Box]:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []
    compiled = [(_compile_pattern(p), p.name) for p in patterns]

    for pno in range(len(doc)):
        page = doc.load_page(pno)
        words = page.get_text("words")
        tokens = [w[4] for w in words]
        text_joined = " ".join(tokens)
        acc = 0

        for comp, pname in compiled:
            for m in comp.finditer(text_joined):
                matched = m.group(0)
                start_char, end_char = m.span()
                start_idx = end_idx = None
                acc = 0
                for i, t in enumerate(tokens):
                    if i > 0:
                        acc += 1
                    token_start, token_end = acc, acc + len(t)
                    if token_end > start_char and token_start < end_char:
                        if start_idx is None:
                            start_idx = i
                        end_idx = i + 1
                    acc += len(t)
                if start_idx is None or end_idx is None:
                    continue
                rects = _word_spans_to_rect(words, [(start_idx, end_idx)])
                for r in rects:
                    boxes.append(
                        Box(
                            page=pno,
                            x0=float(r.x0),
                            y0=float(r.y0),
                            x1=float(r.x1),
                            y1=float(r.y1),
                            matched_text=matched,
                            pattern_name=pname,
                        )
                    )
    doc.close()
    return boxes


# ---------------------------------------------------------
# 2) 실제 시각적 마스킹(블랙박스) 적용
# ---------------------------------------------------------
def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill="black") -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    color = (0, 0, 0) if fill == "black" else (1, 1, 1)
    by_page = {}
    for b in boxes:
        by_page.setdefault(b.page, []).append(b)

    for pno, page_boxes in by_page.items():
        page = doc.load_page(pno)
        for b in page_boxes:
            rect = fitz.Rect(b.x0, b.y0, b.x1, b.y1)
            page.add_redact_annot(rect, fill=color)
        page.apply_redactions()

    out = io.BytesIO()
    doc.save(out)
    doc.close()
    return out.getvalue()


# ---------------------------------------------------------
# 3) 외부에서 호출할 메인 함수
# ---------------------------------------------------------
def apply_text_redaction(file_bytes: bytes) -> bytes:
    """
    전체 PDF에 대해 민감정보를 탐지하고 실제 검정 박스 마스킹 적용.
    """
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(file_bytes, patterns)
    logger.info(f"PDF redaction: {len(boxes)} boxes found")
    return apply_redaction(file_bytes, boxes, fill="black")


# ---------------------------------------------------------
# 4) 텍스트 추출용 (프리뷰용)
# ---------------------------------------------------------
def extract_text(file_bytes: bytes):
    text = ""
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    pages = []
    for i, page in enumerate(doc):
        page_text = page.get_text("text")
        text += page_text or ""
        pages.append({"page": i + 1, "text": page_text})
    doc.close()
    return {"full_text": text, "pages": pages}
