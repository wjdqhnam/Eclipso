# server/modules/ocr_module.py
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple
import re

import numpy as np
from paddleocr import PaddleOCR


@dataclass
class OcrItem:
    bbox: Tuple[float, float, float, float]
    text: str
    score: float


_ocr = PaddleOCR(
    use_doc_orientation_classify=False,
    use_doc_unwarping=False,
    use_textline_orientation=False,
    lang="korean",
)

# ── 카드번호/멀티라인 카드 후보 처리를 위한 유틸 ──────────────────────────────

# 일반적인 카드번호 패턴: 4-4-4-4 (구분자는 공백/하이픈 허용)
_CARD_FULL_RE = re.compile(r"(?:\d{4}[- ]?){3}\d{4}")

# 일반적인 이메일 패턴 (멀티라인 병합에도 재사용)
_EMAIL_FULL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)


def _digits_only(text: str) -> str:
    return re.sub(r"\D", "", text or "")


def _format_card_16(digits: str) -> str:
    """16자리 숫자를 표준 카드번호 포맷(####-####-####-####)으로 변환."""
    d = (digits or "").strip()
    if len(d) != 16:
        return d
    return f"{d[0:4]}-{d[4:8]}-{d[8:12]}-{d[12:16]}"


def _union_bbox(
    b1: Tuple[float, float, float, float],
    b2: Tuple[float, float, float, float],
) -> Tuple[float, float, float, float]:
    x0_1, y0_1, x1_1, y1_1 = b1
    x0_2, y0_2, x1_2, y1_2 = b2
    return (
        float(min(x0_1, x0_2)),
        float(min(y0_1, y0_2)),
        float(max(x1_1, x1_2)),
        float(max(y1_1, y1_2)),
    )


def _is_vertically_stacked(
    b1: Tuple[float, float, float, float],
    b2: Tuple[float, float, float, float],
) -> bool:
    """b2가 b1 바로 아래 줄에 있는지(세로로 쌓인 카드번호 후보인지) 판단."""
    x0_1, y0_1, x1_1, y1_1 = b1
    x0_2, y0_2, x1_2, y2_2 = b2

    if y0_2 <= y0_1:
        return False

    overlap_x = min(x1_1, x1_2) - max(x0_1, x0_2)
    if overlap_x <= 0:
        return False

    h1 = y1_1 - y0_1
    h2 = y2_2 - y0_2
    if h1 <= 0 or h2 <= 0:
        return False

    vertical_gap = y0_2 - y1_1
    if vertical_gap < -0.1 * max(h1, h2):
        return False
    if vertical_gap > 1.5 * max(h1, h2):
        return False

    return True


def _merge_multiline_card_candidates(items: List[OcrItem]) -> List[OcrItem]:
    """
    OCR 결과 중에서 카드번호가 두 줄로 잘려 있는 경우를 합쳐서
    하나의 OcrItem(bbox, text=정규화된 카드번호)으로 만든다.
    """
    if not items:
        return items

    sorted_items = sorted(items, key=lambda it: (it.bbox[1], it.bbox[0]))
    used = [False] * len(sorted_items)
    merged: List[OcrItem] = []

    for i, it in enumerate(sorted_items):
        if used[i]:
            continue

        text1 = it.text or ""
        digits1 = _digits_only(text1)

        if len(digits1) == 16 and _CARD_FULL_RE.search(text1):
            normalized = _format_card_16(digits1)
            merged.append(
                OcrItem(
                    bbox=it.bbox,
                    text=normalized,
                    score=it.score,
                )
            )
            used[i] = True
            continue

        j_merged = None
        for j in range(i + 1, len(sorted_items)):
            if used[j]:
                continue

            it2 = sorted_items[j]
            if not _is_vertically_stacked(it.bbox, it2.bbox):
                continue

            text2 = it2.text or ""
            digits2 = _digits_only(text2)

            digits_combined = digits1 + digits2

            if (
                8 <= len(digits1) <= 16
                and 1 <= len(digits2) <= 8
                and len(digits_combined) == 16
            ):
                normalized = _format_card_16(digits_combined)
                if _CARD_FULL_RE.search(normalized):
                    j_merged = j
                    merged_bbox = _union_bbox(it.bbox, it2.bbox)
                    merged.append(
                        OcrItem(
                            bbox=merged_bbox,
                            text=normalized,
                            score=min(it.score, it2.score),
                        )
                    )
                    used[i] = True
                    used[j] = True
                    break

        if j_merged is None and not used[i]:
            used[i] = True
            merged.append(it)

    return merged


def _merge_multiline_email_candidates(items: List[OcrItem]) -> List[OcrItem]:
    """차트 축 레이블처럼 이메일이 두 줄로 잘려 있는 경우
    (예: 'bonam0806@naver.' + 'com')를 하나의 OcrItem으로 합친다."""
    if not items:
        return items

    sorted_items = sorted(items, key=lambda it: (it.bbox[1], it.bbox[0]))
    used = [False] * len(sorted_items)
    merged: List[OcrItem] = []

    for i, it in enumerate(sorted_items):
        if used[i]:
            continue

        text1 = it.text or ""

        if _EMAIL_FULL_RE.search(text1):
            used[i] = True
            merged.append(it)
            continue

        if "@" not in text1:
            used[i] = True
            merged.append(it)
            continue

        merged_this = False

        for j in range(i + 1, len(sorted_items)):
            if used[j]:
                continue

            it2 = sorted_items[j]
            text2 = it2.text or ""

            if "@" in text2:
                break

            combined = (text1 + text2).replace(" ", "")

            if _EMAIL_FULL_RE.search(combined):
                used[i] = True
                used[j] = True
                merged_bbox = _union_bbox(it.bbox, it2.bbox)
                merged.append(
                    OcrItem(
                        bbox=merged_bbox,
                        text=combined,
                        score=min(it.score, it2.score),
                    )
                )
                merged_this = True
                break

        if not merged_this and not used[i]:
            used[i] = True
            merged.append(it)

    return merged


# ─────────────────────────────────────────────────────────────
# 메인 OCR 진입점
# ─────────────────────────────────────────────────────────────
def run_paddle_ocr(image: np.ndarray, min_score: float = 0.5) -> List[OcrItem]:
    outputs = _ocr.predict(image)
    out: List[OcrItem] = []

    if not outputs:
        return out

    if isinstance(outputs, list) and isinstance(outputs[0], dict):
        data = outputs[0]
        if not isinstance(data, dict):
            return out

        rec_texts = data.get("rec_texts") or []
        rec_scores = data.get("rec_scores") or []

        boxes = data.get("rec_boxes", None)
        if boxes is None:
            boxes = data.get("dt_polys", None)
        if boxes is None:
            return out

        boxes_arr = np.asarray(boxes, dtype=float)

        if boxes_arr.ndim == 2 and boxes_arr.shape[1] == 8:
            boxes_arr = boxes_arr.reshape(-1, 4, 2)

        for txt, score, box in zip(rec_texts, rec_scores, boxes_arr):
            if not txt:
                continue
            s = float(score)
            if s < min_score:
                continue

            coords = np.asarray(box, dtype=float).reshape(-1, 2)
            xs = coords[:, 0]
            ys = coords[:, 1]
            x0, y0 = xs.min(), ys.min()
            x1, y1 = xs.max(), ys.max()

            out.append(
                OcrItem(
                    bbox=(float(x0), float(y0), float(x1), float(y1)),
                    text=str(txt).strip(),
                    score=s,
                )
            )

    out = _merge_multiline_card_candidates(out)
    out = _merge_multiline_email_candidates(out)
    return out
