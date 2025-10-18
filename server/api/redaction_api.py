# server/routes_redaction.py
from __future__ import annotations

import json
import logging
import time
from typing import List, Optional, Literal, Tuple, Set

from fastapi import APIRouter, UploadFile, File, Form, Response, HTTPException
from server.core.schemas import DetectResponse, PatternItem, Box
from server.modules.pdf_module import detect_boxes_from_patterns, apply_redaction
from server.core.redaction_rules import PRESET_PATTERNS


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

def _default_patterns() -> List[PatternItem]:
    return [PatternItem(**p) for p in PRESET_PATTERNS]

def _parse_patterns_json(patterns_json: Optional[str]) -> List[PatternItem]:
    if not patterns_json:
        return _default_patterns()
    try:
        obj = json.loads(patterns_json)
        if isinstance(obj, dict) and "patterns" in obj:
            obj = obj["patterns"]
        return [PatternItem(**p) for p in obj]
    except Exception as e:
        log.exception("patterns_json 파싱 실패: %s", e)
        raise HTTPException(status_code=400, detail=f"잘못된 patterns_json: {e}")

def _parse_boxes_json(boxes_json: Optional[str]) -> List[Box]:
    if not boxes_json:
        return []
    try:
        obj = json.loads(boxes_json)
        if isinstance(obj, dict) and "boxes" in obj:
            obj = obj["boxes"]
        return [Box(**b) for b in obj]
    except Exception as e:
        log.exception("boxes_json 파싱 실패: %s", e)
        raise HTTPException(status_code=400, detail=f"잘못된 boxes_json: {e}")

def _boxes_from_req(req: Optional[str]) -> Tuple[List[Box], Optional[str]]:

    if not req:
        return [], None
    try:
        data = json.loads(req)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"잘못된 req JSON: {e}")

    boxes: List[Box] = []
    fill_override: Optional[str] = None

    if isinstance(data, dict):
        if "fill" in data and isinstance(data["fill"], str):
            fill_override = data["fill"]
        if "boxes" in data and isinstance(data["boxes"], list):
            boxes = [Box(**b) for b in data["boxes"]]
        elif isinstance(data.get("boxes"), dict) and "boxes" in data["boxes"]:
            boxes = [Box(**b) for b in data["boxes"]["boxes"]]
    elif isinstance(data, list):
        boxes = [Box(**b) for b in data]

    return boxes, fill_override

def _split_csv_set(s: Optional[str]) -> Set[str]:
    if not s:
        return set()
    return {x.strip() for x in s.split(",") if x.strip()}

def _filter_boxes(
    boxes: List[Box],
    include_patterns: Set[str],
    exclude_patterns: Set[str],
) -> Tuple[List[Box], dict]:

    stats = {
        "total": len(boxes),
        "by_pattern_before": {},
        "by_pattern_after": {},
        "excluded_reasons": {},  # {pattern: count}
        "include_mode": bool(include_patterns),
        "exclude_set": sorted(list(exclude_patterns)),
        "include_set": sorted(list(include_patterns)),
    }

    for p in set(b.pattern_name for b in boxes):
        stats["by_pattern_before"][p] = sum(1 for b in boxes if b.pattern_name == p)

    def _keep(b: Box) -> bool:
        p = (b.pattern_name or "").strip()
        if include_patterns and p not in include_patterns:
            stats["excluded_reasons"][p] = stats["excluded_reasons"].get(p, 0) + 1
            return False
        if p in exclude_patterns:
            stats["excluded_reasons"][p] = stats["excluded_reasons"].get(p, 0) + 1
            return False
        return True

    out = [b for b in boxes if _keep(b)]

    for p in set(b.pattern_name for b in out):
        stats["by_pattern_after"][p] = sum(1 for b in out if b.pattern_name == p)

    return out, stats

def _dedup_boxes(boxes: List[Box], tol: float = 0.25) -> List[Box]:
    out: List[Box] = []
    def same(a: Box, b: Box) -> bool:
        return (
            a.page == b.page and
            abs(a.x0 - b.x0) <= tol and
            abs(a.y0 - b.y0) <= tol and
            abs(a.x1 - b.x1) <= tol and
            abs(a.y1 - b.y1) <= tol
        )
    for b in boxes:
        if not any(same(b, x) for x in out):
            out.append(b)
    return out

@router.get("/patterns")
def list_patterns():
    return {"patterns": PRESET_PATTERNS}

@router.post("/redactions/detect", response_model=DetectResponse)
async def detect(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(None, description="옵션: List[PatternItem] 또는 {'patterns':[...]} JSON"),
):
    _ensure_pdf(file)
    t0 = time.perf_counter()
    pdf = await file.read()
    patterns = _parse_patterns_json(patterns_json)

    log.debug("DETECT request: size=%dB patterns=%s",
            len(pdf), [p.name for p in patterns])

    boxes = detect_boxes_from_patterns(pdf, patterns)
    elapsed = (time.perf_counter() - t0) * 1000
    log.debug("DETECT done: total_matches=%d elapsed=%.2fms", len(boxes), elapsed)
    return DetectResponse(total_matches=len(boxes), boxes=boxes)

@router.post("/redactions/apply", response_class=Response)
async def apply(
    file: UploadFile = File(..., description="PDF 파일"),
    req: Optional[str] = Form(None, description='기존 형식: {"boxes":[...], "fill":"black|white"}'),
    boxes_json: Optional[str] = Form(None, description="List[Box] 또는 {'boxes':[...]}"),
    fill: Optional[str] = Form("black", description="'black' 또는 'white'"),
    patterns_json: Optional[str] = Form(None, description="자동 감지 시 사용할 패턴 JSON(없으면 PRESET)"),
    mode: Literal["strict", "auto_all", "auto_merge"] = Form(
        "strict",
        description=(
            "strict: 받은 boxes만 적용 (기존 동작) | "
            "auto_all: boxes 무시, 서버 감지 전체 적용 | "
            "auto_merge: 받은 boxes + 서버 감지 결과 합쳐 적용"
        ),
    ),
    exclude_patterns: Optional[str] = Form(
        None,
        description="콤마구분. 지정된 패턴은 레닥션에서 제외. 예: 'card,passport'",
    ),
    include_patterns: Optional[str] = Form(
        None,
        description="콤마구분 allowlist. 지정되면 해당 패턴만 적용. 예: 'email,phone_mobile'",
    ),
    ensure_patterns: Optional[str] = Form(
        "card",
        description="서버가 추가 감지해 반드시 포함시킬 패턴(콤마구분). 기본: 'card'",
    ),
):
    _ensure_pdf(file)
    pdf = _read_pdf(file)
    t0 = time.perf_counter()

    boxes_req, fill_override = _boxes_from_req(req)
    if fill_override:
        fill = fill_override or fill
    if boxes_json is not None:
        boxes_req = _parse_boxes_json(boxes_json)

    patterns = _parse_patterns_json(patterns_json)
    excl = _split_csv_set(exclude_patterns)
    incl = _split_csv_set(include_patterns)
    ensure = _split_csv_set(ensure_patterns) or set()

    log.debug(
        "APPLY request: mode=%s, file_size=%dB, boxes_req=%d, fill=%s, patterns=%s, "
        "exclude=%s, include=%s, ensure=%s",
        mode, len(pdf), len(boxes_req), fill,
        [p.name for p in patterns], sorted(list(excl)), sorted(list(incl)), sorted(list(ensure))
    )

    if mode == "auto_all":
        detected = detect_boxes_from_patterns(pdf, patterns)
        base_boxes = detected
    elif mode == "auto_merge":
        detected = detect_boxes_from_patterns(pdf, patterns)
        base_boxes = (boxes_req or []) + detected
    else:  # strict
        base_boxes = boxes_req or []
        if ensure:
            ensure_detected = detect_boxes_from_patterns(pdf, patterns)
            ensured = [b for b in ensure_detected if (b.pattern_name or "") in ensure]
            log.debug(
                "APPLY strict: ensure_patterns=%s detected=%d -> merge=%d",
                sorted(list(ensure)), len(ensure_detected), len(ensured)
            )
            if ensured:
                base_boxes = _dedup_boxes(base_boxes + ensured)

        if not base_boxes:
            raise HTTPException(status_code=400, detail="boxes가 비어있습니다. (mode=strict)")

    final_boxes, stats = _filter_boxes(base_boxes, include_patterns=incl, exclude_patterns=excl)

    log.debug(
        "APPLY build: before_total=%d after_total=%d include_mode=%s include=%s exclude=%s "
        "by_pattern_before=%s by_pattern_after=%s excluded_reasons=%s",
        stats["total"],
        len(final_boxes),
        stats["include_mode"],
        stats["include_set"],
        stats["exclude_set"],
        stats["by_pattern_before"],
        stats["by_pattern_after"],
        stats["excluded_reasons"],
    )

    out = apply_redaction(pdf, final_boxes, fill=fill or "black")
    elapsed = (time.perf_counter() - t0) * 1000
    log.debug("APPLY done: bytes_out=%d elapsed=%.2fms", len(out), elapsed)

    return Response(
        content=out,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename=\"redacted.pdf\"'},
    )

def match_text(text: str):
    import re
    from ..core.redaction_rules import PRESET_PATTERNS
    import traceback

    try:
        if not isinstance(text, str):
            print("[match_text] text 타입:", type(text))
            text = str(text)

        matches = []
        counts = {}

        for rule in PRESET_PATTERNS:
            pattern = rule.get("regex")
            name = rule.get("name", "")
            if not pattern:
                continue

            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error as err:
                print(f"정규식 컴파일 실패: {name} ({err})")
                continue

            found = list(regex.finditer(text))
            counts[name] = len(found)

            for m in found:
                ctx_start = max(0, m.start() - 20)
                ctx_end = min(len(text), m.end() + 20)
                matches.append({
                    "rule": name,
                    "value": m.group(),
                    "start": m.start(),
                    "end": m.end(),
                    "context": text[ctx_start:ctx_end],
                    "valid": True,
                })

        print(f"매칭 완료: 총 {len(matches)}개 발견")
        return {"items": matches, "counts": counts}

    except Exception as e:
        print("match_text 내부 오류:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"매칭 오류: {e}")
