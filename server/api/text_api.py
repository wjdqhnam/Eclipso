from __future__ import annotations
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, UploadFile, File, Body, HTTPException, Request
from pathlib import Path
import tempfile, os

from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY
from server.modules import pdf_module
from server.utils.file_reader import extract_from_file 
router = APIRouter(prefix="/text", tags=["text"])


def _ensure_full_text_payload(raw: Any) -> Dict[str, str]:
    if raw is None:
        return {"full_text": ""}
    if isinstance(raw, dict):
        txt = raw.get("full_text") or raw.get("text") or raw.get("content") or ""
        return {"full_text": str(txt or "")}
    if isinstance(raw, (bytes, bytearray)):
        try:
            return {"full_text": raw.decode("utf-8", "ignore")}
        except Exception:
            return {"full_text": ""}
    return {"full_text": str(raw or "")}



@router.post(
    "/extract",
    summary="파일에서 텍스트 추출",
    description="업로드한 문서에서 본문 텍스트를 추출하여 항상 {'full_text': ...}로 반환"
)
async def extract_text(file: UploadFile = File(...)):
    try:
        ext = Path(file.filename or "").suffix.lower()
        data = await file.read()
        if not data:
            raise HTTPException(status_code=400, detail="빈 파일입니다.")


        if ext == ".pdf":
            text = pdf_module.extract_text(data)  
            return {"full_text": text or ""}

        try:
            res = await extract_from_file(file)
        except TypeError:
            with tempfile.TemporaryDirectory() as td:
                src = os.path.join(td, f"src{ext or ''}")
                with open(src, "wb") as f:
                    f.write(data)
                res = {"full_text": ""}

        return _ensure_full_text_payload(res)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"서버 내부 오류: {e}")


@router.get(
    "/rules",
    summary="정규식 규칙 이름 목록",
    description="서버에 등록된 개인정보 정규식 규칙들의 이름 배열을 반환"
)
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]


@router.post(
    "/match",
    summary="정규식 매칭 실행",
    description="입력 텍스트에 대해 정규식 기반 개인정보 패턴(시작/끝 인덱스, 라벨 등)을 탐지하여 반환"
)
async def match(req: Dict[str, Any] = Body(...)):
    text = (req or {}).get("text", "") or ""
    return match_text(text)



@router.get(
    "/policy",
    summary="기본 병합 정책 조회",
    description="정규식·NER 탐지 결과를 병합할 때 사용하는 서버의 기본 정책을 반환"
)
async def get_policy():
    return DEFAULT_POLICY


@router.put(
    "/policy",
    summary="병합 정책 설정",
    description="허용 라벨/우선순위 등 병합 정책을 갱신(그대로 반환)"
)
async def set_policy(policy: Dict[str, Any] = Body(...)):
    return {"ok": True, "policy": policy}


@router.post(
    "/detect",
    summary="정규식+NER 통합 탐지",
    description=(
        "정규식과 NER을 선택적으로 실행하고 정책에 따라 결과를 병합하여 반환\n"
        "- options.run_regex, options.run_ner로 실행 여부 제어\n"
        "- policy를 함께 전달하면 기본 정책 대신 해당 정책 사용"
    ),
)
async def detect(req: Dict[str, Any] = Body(...)):
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = (req or {}).get("policy") or DEFAULT_POLICY

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

    # 1) 정규식
    regex_result = match_text(text) if run_regex_opt else {"items": []}
    regex_spans: List[Dict[str, Any]] = []
    for it in (regex_result.get("items") or []):
        s, e = it.get("start"), it.get("end")
        if s is None or e is None or e <= s:
            continue
        label = it.get("label") or it.get("name") or it.get("rule") or "REGEX"
        regex_spans.append({
            "start": int(s),
            "end": int(e),
            "label": str(label),
            "source": "regex",
            "score": None,
        })

    # 2) NER
    ner_spans: List[Dict[str, Any]] = []
    ner_raw_preview: Any = None
    if run_ner_opt:
        try:
            from server.api.ner_api import ner_predict_blocking
            raw_res = ner_predict_blocking(text, labels=policy.get("allowed_labels"))
            ner_raw_preview = raw_res.get("raw")
        except Exception:
            ner_raw_preview = {"error": "ner_raw_preview_failed"}
        from server.modules.ner_module import run_ner as _run_ner
        ner_spans = _run_ner(text=text, policy=policy)

    # 3) 병합
    merger = MergePolicy(policy)
    final_spans, report = merger.merge(text, regex_spans, ner_spans, degrade=(run_ner_opt is False))

    return {
        "text": text,
        "final_spans": final_spans,
        "report": report,
        "debug": {
            "run_regex": run_regex_opt,
            "run_ner": run_ner_opt,
            "ner_span_count": len(ner_spans),
            "ner_span_head": ner_spans[:5],
            "ner_raw_preview": ner_raw_preview,
        },
    }


@router.post("/ner")
async def ner_detect(
    request: Request,
    text: Optional[str] = Body(None),
    file: Optional[UploadFile] = File(None),
):
    try:
        if (text is None) and request.headers.get("content-type", "").startswith("application/json"):
            try:
                data = await request.json()
                text = (data or {}).get("text")
            except Exception:
                pass
        if (text is None or not str(text).strip()) and file is not None:
            blob = await file.read()
            if blob:
                try:
                    text = pdf_module.extract_text(blob)
                except Exception:
                    text = ""
        if not text or not str(text).strip():
            return {"items": [], "counts": {}}

        policy = dict(DEFAULT_POLICY)

        regex_res = match_text(text)
        regex_spans: List[Dict[str, Any]] = []
        for it in (regex_res.get("items") or []):
            s, e = it.get("start"), it.get("end")
            if s is None or e is None or e <= s:
                continue
            label = it.get("label") or it.get("name") or it.get("rule") or "REGEX"
            regex_spans.append({"start": int(s), "end": int(e), "label": str(label), "source": "regex", "score": None})

        from server.modules.ner_module import run_ner as _run_ner
        ner_spans = _run_ner(text=str(text), policy=policy)

        def _overlap(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
            return min(int(a["end"]), int(b["end"])) > max(int(a["start"]), int(b["start"]))

        ner_only = [n for n in ner_spans if not any(_overlap(n, r) for r in regex_spans)]

        items: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {}
        for s in ner_only:
            start, end = int(s["start"]), int(s["end"])
            label = str(s.get("label") or "").strip()
            score = s.get("score", None)
            frag = str(text)[start:end]
            items.append({
                "label": label,
                "text": frag,
                "start": start,
                "end": end,
                "score": float(score) if isinstance(score, (int, float)) else None,
            })
            counts[label] = counts.get(label, 0) + 1

        return {"items": items, "counts": counts}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NER 탐지 오류: {e}")
