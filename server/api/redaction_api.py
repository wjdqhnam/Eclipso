from __future__ import annotations

import json
import logging
import time
import re
import types
from typing import Dict, List, Optional, Literal, Tuple, Set, Any
from urllib.parse import quote

from fastapi import APIRouter, UploadFile, File, Form, Response, HTTPException

from server.core.schemas import DetectResponse, PatternItem, Box
from server.modules.pdf_module import detect_boxes_from_patterns, apply_redaction
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules.common import compile_rules  


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

    if patterns_json is None:
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    s = str(patterns_json).strip()
    if not s or s.lower() in ("null", "none"):
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    try:
        obj = json.loads(s)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail=(
                "잘못된 patterns_json: JSON 파싱 실패. 예: {'patterns': [...]} 또는 [...]. "
                f"구체적 오류: {e}"
            ),
        )

    if isinstance(obj, dict):
        if "patterns" in obj and isinstance(obj["patterns"], list):
            arr = obj["patterns"]
        else:
            raise HTTPException(
                status_code=400,
                detail="잘못된 patterns_json: 'patterns' 키에 리스트 필요",
            )
    elif isinstance(obj, list):
        arr = obj
    else:
        raise HTTPException(
            status_code=400,
            detail="잘못된 patterns_json: 리스트 또는 {'patterns': 리스트} 형태",
        )

    try:
        return [PatternItem(**p) for p in arr]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"잘못된 patterns 항목: {e}")


def _compile_patterns(items: List[PatternItem]) -> List[Any]:
    compiled: List[Any] = []
    for it in items:
        # PatternItem 속성 추출
        try:
            regex = getattr(it, "regex")
        except AttributeError:
            raise HTTPException(status_code=400, detail="PatternItem에 'regex' 누락")

        try:
            rp = re.compile(regex)
        except re.error as e:
            name_for_msg = getattr(it, "name", getattr(it, "label", "UNKNOWN"))
            raise HTTPException(
                status_code=400, detail=f"정규식 컴파일 실패({name_for_msg}): {e}"
            )

        ns = types.SimpleNamespace(**it.dict())
        setattr(ns, "compiled", rp)
        compiled.append(ns)
    return compiled


@router.post(
    "/redactions/detect",
    response_model=DetectResponse,
    summary="PDF 패턴 박스 탐지",
    description=(
        "- 정규식 패턴 → 좌표 박스\n"
        "- 입력: file(PDF), patterns_json(JSON 문자열 | 생략)\n"
        "- 출력: total_matches, boxes"
    ),
)
async def detect(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(None, description="패턴 목록 JSON(옵션)"),
):
    _ensure_pdf(file)
    pdf = await file.read()

    # 로깅(옵션)
    if patterns_json is None:
        log.debug("patterns_json: None")
    else:
        log.debug("patterns_json(len=%d): %r", len(patterns_json), patterns_json[:200])

    items = _parse_patterns_json(patterns_json)
    patterns = _compile_patterns(items)
    boxes = detect_boxes_from_patterns(pdf, patterns)
    return DetectResponse(total_matches=len(boxes), boxes=boxes)


@router.post(
    "/redactions/apply",
    response_class=Response,
    summary="PDF 레닥션 적용",
    description="기본 정규식 패턴으로 레닥션 적용.",
)
async def apply(
    file: UploadFile = File(..., description="PDF 파일"),
):
    _ensure_pdf(file)
    pdf = _read_pdf(file)
    fill = "black"

    boxes = detect_boxes_from_patterns(pdf, [PatternItem(**p) for p in PRESET_PATTERNS])
    out = apply_redaction(pdf, boxes, fill=fill)

    return Response(
        content=out,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="redacted.pdf"'},
    )

# 텍스트 매칭 (정규식 + validator) 
def match_text(text: str):
    try:
        if not isinstance(text, str):
            text = str(text)
        comp = compile_rules()

        matches: List[Dict[str, Any]] = {}
        matches = []
        counts: Dict[str, int] = {}

        for name, rx, need_valid, prio, validator in comp:
            if rx is None:
                continue

            for m in rx.finditer(text):
                s, e = m.span()
                val = m.group(0)

                ok = True
                if need_valid and validator:
                    try:
                        try:
                            ok = bool(validator(val))
                        except TypeError:
                            ok = bool(validator(val, None))
                    except Exception:
                        ok = False  # 검증 중 예외는 FAIL 취급

                ctx_start = max(0, s - 20)
                ctx_end = min(len(text), e + 20)

                matches.append(
                    {
                        "rule": name,
                        "value": val,
                        "start": s,
                        "end": e,
                        "context": text[ctx_start:ctx_end],
                        "valid": ok,
                    }
                )

                # counts 는 OK 만 집계
                if ok:
                    counts[name] = counts.get(name, 0) + 1

        log.debug("regex match count=%d", len(matches))
        return {"items": matches, "counts": counts}

    except Exception as e:  # pragma: no cover
        log.exception("match_text 내부 오류")
        raise HTTPException(status_code=500, detail=f"매칭 오류: {e}")
