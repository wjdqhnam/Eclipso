from __future__ import annotations
from fastapi import APIRouter, UploadFile, HTTPException
from typing import Dict, Any, List

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY

router = APIRouter(prefix="/text", tags=["text"])

# ──────────────────────────────────────────────────────────────────────────────
@router.post(
    "/extract",
    summary="파일에서 텍스트 추출",
    description="업로드한 문서에서 본문 텍스트를 추출하여 반환"
)
async def extract_text(file: UploadFile):
    try:
        return await extract_from_file(file)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(500, detail=f"서버 내부 오류: {e}")

# ──────────────────────────────────────────────────────────────────────────────
@router.get(
    "/rules",
    summary="정규식 규칙 이름 목록",
    description="서버에 등록된 개인정보 정규식 규칙들의 이름 배열을 반환"
)
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]

# ──────────────────────────────────────────────────────────────────────────────
@router.post(
    "/match",
    summary="정규식 매칭 실행",
    description="입력 텍스트에 대해 정규식 기반 개인정보 패턴(시작/끝 인덱스, 라벨 등)을 탐지하여 반환"
)
async def match(req: dict):
    text = (req or {}).get("text", "") or ""
    return match_text(text)

# ──────────────────────────────────────────────────────────────────────────────
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
    description=(
    "허용 라벨/우선순위 등 병합 정책을 갱신.\n"
    "전달된 정책 객체를 그대로 반환"
    )
)
async def set_policy(policy: dict):
    return {"ok": True, "policy": policy}

# ──────────────────────────────────────────────────────────────────────────────
@router.post(
    "/detect",
    summary="정규식+NER 통합 탐지",
    description=(
        '정규식과 NER을 선택적으로 실행하고, 정책에 따라 결과를 병합하여 반환\n'
        '- options.run_regex / options.run_ner 로 각 탐지 실행 여부를 제어\n'
        "- policy를 함께 전달하면 기본 정책 대신 해당 정책이 병합에 사용됨\n"
        '- 테스트 예시: { "text": "홍길동, 생일은 2004-01-01.소속 중부대학교. 주소는 경기도 고양시 덕양구 동헌로 305. 연락처 010-1234--5678.", "options":  "run_regex": true, "run_ner": true } }'
    ),
)
async def detect(req: dict):
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = (req or {}).get("policy") or DEFAULT_POLICY

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

    # 1) 정규식
    regex_result = match_text(text) if run_regex_opt else {"items": []}
    regex_spans: List[Dict[str, Any]] = []
    for it in regex_result.get("items", []):
        s, e = it.get("start"), it.get("end")
        if s is None or e is None or e <= s:
            continue
        label = it.get("label") or it.get("name") or "REGEX"
        regex_spans.append({
            "start": int(s),
            "end": int(e),
            "label": str(label),
            "source": "regex",
            "score": None
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
        from server.modules.ner_module import run_ner
        ner_spans = run_ner(text=text, policy=policy)

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
            "ner_raw_preview": ner_raw_preview
        }
    }
