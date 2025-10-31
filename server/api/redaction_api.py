from __future__ import annotations

import json
import logging
import time
from typing import Dict, List, Optional, Literal, Tuple, Set
from urllib.parse import quote

from fastapi import APIRouter, UploadFile, File, Form, Response, HTTPException
from server.core.schemas import DetectResponse, PatternItem, Box
from server.modules.pdf_module import detect_boxes_from_patterns, apply_redaction
from server.core.redaction_rules import PRESET_PATTERNS
from server.core.matching import find_sensitive_spans

router = APIRouter(tags=["redaction"])
log = logging.getLogger("redaction.router")


def _ensure_pdf(file: UploadFile) -> None:
    if file is None:
        raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")
    if file.content_type not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")


def _read_pdf(file: UploadFile) -> bytes:
    data = file.file.read()
    if not data:
        raise HTTPException(status_code=400, detail="빈 파일입니다.")
    return data


def _parse_patterns_json(patterns_json: Optional[str]) -> List[PatternItem]:
    if not patterns_json:
        return [PatternItem(**p) for p in PRESET_PATTERNS]
    try:
        obj = json.loads(patterns_json)
        if isinstance(obj, dict) and "patterns" in obj:
            obj = obj["patterns"]
        return [PatternItem(**p) for p in obj]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"잘못된 patterns_json: {e}")


@router.post("/redactions/detect", response_model=DetectResponse)
async def detect(file: UploadFile = File(...), patterns_json: Optional[str] = Form(None)):
    _ensure_pdf(file)
    pdf = await file.read()
    patterns = _parse_patterns_json(patterns_json)
    boxes = detect_boxes_from_patterns(pdf, patterns)
    return DetectResponse(total_matches=len(boxes), boxes=boxes)


@router.post("/redactions/apply", response_class=Response)
async def apply(file: UploadFile = File(...), req: Optional[str] = Form(None), fill: str = Form("black")):
    _ensure_pdf(file)
    pdf = _read_pdf(file)
    boxes = detect_boxes_from_patterns(pdf, [PatternItem(**p) for p in PRESET_PATTERNS])
    out = apply_redaction(pdf, boxes, fill=fill)
    return Response(
        content=out,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="redacted.pdf"'},
    )


def match_text(text: str):
    try:
        if not isinstance(text, str):
            text = str(text)

        results = find_sensitive_spans(text)
        matches = []
        counts: Dict[str, int] = {}

        for start, end, value, rule_name in results:
            ctx_start = max(0, start - 20)
            ctx_end = min(len(text), end + 20)
            matches.append({
                "rule": rule_name,
                "value": value,
                "start": start,
                "end": end,
                "context": text[ctx_start:ctx_end],
                "valid": True,
            })
            counts[rule_name] = counts.get(rule_name, 0) + 1

        print(f"매칭 완료: 총 {len(matches)}개 발견")
        return {"items": matches, "counts": counts}

    except Exception as e:
        print("match_text 내부 오류:", e)
        raise HTTPException(status_code=500, detail=f"매칭 오류: {e}")
