from __future__ import annotations

from fastapi import APIRouter, UploadFile, HTTPException
from typing import Dict, Any, List
import re
import logging

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text
from server.modules.pdf_module import extract_markdown as extract_pdf_markdown
from server.modules.ner_module import run_ner

router = APIRouter(prefix="/text", tags=["text"])
logger = logging.getLogger(__name__)

# 기본 병합 정책(없으면 /text/policy에서 NameError 남)
DEFAULT_POLICY: Dict[str, Any] = {
    "chunk_size": 1500,
    "chunk_overlap": 200,
    "allowed_labels": ["PS", "LC", "OG", "DT"],
}

# 줄바꿈 합치기 (PDF text 보정용)
_JOIN_NEWLINE_RE = re.compile(r"([\w\uAC00-\uD7A3.%+\-/])\n([\w\uAC00-\uD7A3.%+\-/])")


def _join_broken_lines(text: str | None) -> str:
    if not text:
        return ""
    t = text.replace("\r\n", "\n")
    prev = None
    while prev != t:
        prev = t
        t = _JOIN_NEWLINE_RE.sub(r"\1\2", t)
    return t


def _normalize_newlines_in_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return _join_broken_lines(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            obj[k] = _normalize_newlines_in_obj(v)
        return obj
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i] = _normalize_newlines_in_obj(v)
        return obj
    return obj


def _effective_policy(user_policy: Any) -> Dict[str, Any]:
    p = dict(DEFAULT_POLICY)
    if isinstance(user_policy, dict):
        p.update(user_policy)
    # allowed_labels가 비어 있으면 기본값 적용
    if not isinstance(p.get("allowed_labels"), list) or not p.get("allowed_labels"):
        p["allowed_labels"] = list(DEFAULT_POLICY["allowed_labels"])
    # chunk_overlap 최소 안전값
    try:
        p["chunk_overlap"] = int(p.get("chunk_overlap", DEFAULT_POLICY["chunk_overlap"]))
    except Exception:
        p["chunk_overlap"] = DEFAULT_POLICY["chunk_overlap"]
    try:
        p["chunk_size"] = int(p.get("chunk_size", DEFAULT_POLICY["chunk_size"]))
    except Exception:
        p["chunk_size"] = DEFAULT_POLICY["chunk_size"]
    return p


# NER 후처리 필터 (핵심)
def _is_valid_ner_span(span: Dict[str, Any]) -> bool:
    text = (span.get("text") or "").strip()
    label = span.get("label")

    if not text:
        return False

    # 특수문자만 있는 경우 제거
    if re.fullmatch(r"[^\w\uAC00-\uD7A3]+", text):
        return False

    # LC(주소)는 최소 길이 제한
    if label == "LC" and len(text) < 5:
        return False

    return True


# /text/extract
@router.post("/extract")
async def extract_text(file: UploadFile):
    try:
        filename = (file.filename or "").lower()
        raw_bytes = await file.read()
        await file.seek(0)

        data = await extract_from_file(file)

        # PDF → Markdown을 full_text로 강제
        if filename.endswith(".pdf"):
            try:
                md_info = extract_pdf_markdown(raw_bytes)
                if md_info.get("markdown"):
                    markdown = md_info["markdown"]
                    data["full_text"] = markdown
                    data["markdown"] = markdown
                    if "pages" in md_info:
                        data["pages"] = [
                            {"page": p.get("page"), "text": p.get("markdown", "")}
                            for p in (md_info.get("pages") or [])
                        ]
            except Exception as e:
                logger.warning("PDF Markdown override 실패: %s", e)

        data = _normalize_newlines_in_obj(data)
        return data

    except Exception as e:
        raise HTTPException(500, detail=str(e))


# /text/policy
@router.get(
    "/policy",
    summary="기본 병합 정책 조회",
    description="정규식·NER 탐지 결과를 병합할 때 사용하는 서버의 기본 정책을 반환",
)
async def get_policy():
    return DEFAULT_POLICY


@router.put(
    "/policy",
    summary="병합 정책 설정",
    description=("허용 라벨/우선순위 등 병합 정책을 갱신.\n" "전달된 정책 객체를 그대로 반환"),
)
async def set_policy(policy: dict):
    return {"ok": True, "policy": policy}


# /text/rules
@router.get(
    "/rules",
    summary="정규식 규칙 이름 목록",
    description="서버에 등록된 개인정보 정규식 규칙들의 이름 배열을 반환",
)
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]


# /text/match
@router.post(
    "/match",
    summary="정규식 매칭 실행",
    description="입력 텍스트에 대해 정규식 기반 개인정보 패턴(시작/끝 인덱스, 라벨 등)을 탐지하여 반환",
)
async def match(req: dict):
    text = (req or {}).get("text", "") or ""
    return match_text(text)


# /text/detect (정규식 + NER)
@router.post("/detect")
async def detect(req: dict):
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = _effective_policy((req or {}).get("policy") or {})

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

    # 1) 정규식 탐지
    regex_spans: List[Dict[str, Any]] = []
    if run_regex_opt:
        regex_result = match_text(text)
        for it in (regex_result.get("items", []) or []):
            if it.get("valid") is False:
                continue
            s, e = it.get("start"), it.get("end")
            if s is None or e is None:
                continue
            try:
                s_i = int(s)
                e_i = int(e)
            except Exception:
                continue
            if e_i <= s_i:
                continue

            regex_spans.append(
                {
                    "start": s_i,
                    "end": e_i,
                    "label": it.get("label") or it.get("rule"),
                    "text": text[s_i:e_i],
                    "source": "regex",
                    "score": None,
                }
            )

    # 2) NER 탐지 (외부 마스킹 삭제, exclude_spans 전달)
    ner_spans: List[Dict[str, Any]] = []
    if run_ner_opt:
        ner_spans = run_ner(text=text, policy=policy, exclude_spans=regex_spans)
        for sp in ner_spans:
            sp["source"] = "ner"

    # 3) 병합 + 필터링
    final_spans: List[Dict[str, Any]] = []
    for sp in (regex_spans + ner_spans):
        # 정규식에서 잡힌 LC는 제거
        if sp.get("source") == "regex" and sp.get("label") == "LC":
            continue
        if not _is_valid_ner_span(sp):
            continue
        final_spans.append(sp)

    final_spans.sort(key=lambda x: (x["start"], x["end"]))

    return {
        "text": text,
        "final_spans": final_spans,
        "report": {
            "regex": len(regex_spans),
            "ner": len(ner_spans),
            "final": len(final_spans),
        },
    }


# /text/markdown
@router.post("/markdown")
async def extract_markdown_endpoint(file: UploadFile):
    filename = (file.filename or "").lower()
    if not filename.endswith(".pdf"):
        raise HTTPException(400, "PDF만 지원")

    pdf_bytes = await file.read()
    data = extract_pdf_markdown(pdf_bytes)
    return _normalize_newlines_in_obj(data)
