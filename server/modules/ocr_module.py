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

# ── 카드번호처럼 줄바꿈으로 잘린 숫자 시퀀스를 재조합하기 위한 유틸 ────────────────

_CARD_FULL_RE = re.compile(r"(?:\d{4}[- ]?){3}\d{4}")


def _digits_only(text: str) -> str:
    return re.sub(r"\D", "", text or "")


def _union_bbox(b1: Tuple[float, float, float, float],
                b2: Tuple[float, float, float, float]) -> Tuple[float, float, float, float]:

    x0_1, y0_1, x1_1, y1_1 = b1
    x0_2, y0_2, x1_2, y1_2 = b2
    return (
        float(min(x0_1, x0_2)),
        float(min(y0_1, y0_2)),
        float(max(x1_1, x1_2)),
        float(max(y1_1, y1_2)),
    )


def _is_vertically_stacked(b1: Tuple[float, float, float, float],
                            b2: Tuple[float, float, float, float]) -> bool:
    x0_1, y0_1, x1_1, y1_1 = b1
    x0_2, y0_2, x1_2, y1_2 = b2


    if y0_2 <= y0_1:
        return False


    overlap_x = min(x1_1, x1_2) - max(x0_1, x0_2)
    if overlap_x <= 0:
        return False

    h1 = y1_1 - y0_1
    h2 = y1_2 - y0_2
    if h1 <= 0 or h2 <= 0:
        return False

    vertical_gap = y0_2 - y1_1  


    if vertical_gap < -0.1 * max(h1, h2):
        return False
    if vertical_gap > 1.5 * max(h1, h2):
        return False

    return True


def _merge_multiline_card_candidates(items: List[OcrItem]) -> List[OcrItem]:
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

        if _CARD_FULL_RE.search(text1) and len(digits1) == 16:
            merged.append(it)
            continue
        j = i + 1
        merged_this = False

        if j < len(sorted_items) and not used[j]:
            it2 = sorted_items[j]
            text2 = it2.text or ""
            digits2 = _digits_only(text2)
            digits_combined = digits1 + digits2
            if 8 <= len(digits1) <= 16 and 1 <= len(digits2) <= 8 and len(digits_combined) == 16:
                if _is_vertically_stacked(it.bbox, it2.bbox):
                    candidate = f"{text1} {text2}".strip()
                    if _CARD_FULL_RE.search(candidate):
                        used[i] = True
                        used[j] = True
                        merged_bbox = _union_bbox(it.bbox, it2.bbox)
                        merged.append(
                            OcrItem(
                                bbox=merged_bbox,
                                text=candidate,
                                score=min(it.score, it2.score),
                            )
                        )
                        merged_this = True

        if not merged_this and not used[i]:
            used[i] = True
            merged.append(it)

    return merged


def run_paddle_ocr(image: np.ndarray, min_score: float = 0.5) -> List[OcrItem]:
    outputs = _ocr.predict(image)
    out: List[OcrItem] = []

    for res in outputs:
        data = getattr(res, "res", None)
        if data is None and isinstance(res, dict):
            data = res.get("res", res)
        if not isinstance(data, dict):
            continue

        rec_texts = data.get("rec_texts") or []
        rec_scores = data.get("rec_scores") or []

        boxes = data.get("rec_boxes", None)
        if boxes is None:
            boxes = data.get("dt_polys", None)
        if boxes is None:
            continue

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

    return out