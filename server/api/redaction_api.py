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


def _run_validator(value: str, validator) -> bool:
    if not callable(validator):
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            # 일부 validator는 (value, opts) 형태를 사용하므로 두 번째 인자를 None으로 보냄
            return bool(validator(value, None))
    except Exception:
        return False


def _ensure_pdf(file: UploadFile) -> None:
    if file is None:
        raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")
    if file.content_type not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(status_code=400, detail="PDF 파일이 아닙니다.")


def _read_pdf(file: UploadFile) -> bytes:
    try:
        return file.file.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF 읽기 실패: {e}")


def _load_patterns_json(patterns_json: Optional[str]) -> List[PatternItem]:
    if not patterns_json:
        # 없는 경우 기본 PRESET_PATTERNS 사용
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    try:
        obj = json.loads(patterns_json)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"patterns_json 파싱 실패: {e}")

    arr: List[Dict[str, Any]]
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
        raise HTTPException(status_code=400, detail=f"잘못된 PatternItem 형식: {e}")


@router.post(
    "/redactions/detect",
    response_model=DetectResponse,
    summary="PDF 패턴 박스 탐지",
    description=(
        "PDF에서 정규식/패턴에 해당하는 텍스트 박스를 탐지하여"
        " 좌표(Box 리스트)로 반환한다."
    ),
)
async def detect(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(
        None,
        description="커스텀 패턴 정의(JSON 문자열, 생략 시 PRESET_PATTERNS 사용)",
    ),
):
    _ensure_pdf(file)
    pdf_bytes = _read_pdf(file)

    # 패턴 로드
    patterns = _load_patterns_json(patterns_json)

    # 기본 구현은 PRESET_PATTERNS 그대로 사용
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)
    return DetectResponse(
        ok=True,
        patterns=patterns,
        boxes=boxes,
        preview_url=None,
    )


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

    boxes = detect_boxes_from_patterns(
        pdf, [PatternItem(**p) for p in PRESET_PATTERNS]
    )
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

        # 공통 규칙 컴파일 (name, regex, need_valid, prio, validator)
        comp = compile_rules()

        matches: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {}

        for rule_name, rx, need_valid, _prio, validator in comp:
            if rx is None:
                continue

            for m in rx.finditer(text):
                value = m.group(0)

                # --- validator로 OK / FAIL 판단 -------------------
                # need_valid가 True이고 validator가 붙어 있으면 유효성 검사 실행
                is_valid = True
                if need_valid:
                    is_valid = _run_validator(value, validator)

                start = m.start()
                end = m.end()
                ctx_start = max(0, start - 20)
                ctx_end = min(len(text), end + 20)

                # ⚠️ 유효/무효와 상관없이 "정규식에 한 번 걸렸으면" 전부 기록
                matches.append(
                    {
                        "rule": rule_name,
                        "value": value,
                        "start": start,
                        "end": end,
                        "context": text[ctx_start:ctx_end],
                        "valid": bool(is_valid),
                    }
                )

                # counts에는 OK/FAIL 합계(= 정규식 매칭 총 개수)를 넣어준다.
                counts[rule_name] = counts.get(rule_name, 0) + 1

        log.debug(
            "regex match count(total incl. invalid)=%d, rules=%d",
            len(matches),
            len(counts),
        )
        return {"items": matches, "counts": counts}

    except Exception as e:
        log.exception("match_text 내부 오류")
        raise HTTPException(status_code=500, detail=f"매칭 오류: {e}")
