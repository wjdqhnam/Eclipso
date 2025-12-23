from __future__ import annotations

from fastapi import APIRouter, UploadFile, HTTPException
from typing import Dict, Any, List
import logging

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text
from server.modules import pdf_module
from server.modules.pdf_module import extract_markdown as extract_pdf_markdown
from server.modules.ner_module import run_ner

router = APIRouter(prefix="/text", tags=["text"])
logger = logging.getLogger(__name__)

DEFAULT_POLICY: Dict[str, Any] = {
    "chunk_size": 1500,
    "chunk_overlap": 200,
    "allowed_labels": ["PS", "LC", "OG"],
}

def _effective_policy(user_policy: Any) -> Dict[str, Any]:
    p = dict(DEFAULT_POLICY)
    if isinstance(user_policy, dict):
        p.update(user_policy)
    if not isinstance(p.get("allowed_labels"), list) or not p.get("allowed_labels"):
        p["allowed_labels"] = list(DEFAULT_POLICY["allowed_labels"])
    try:
        p["chunk_overlap"] = int(p.get("chunk_overlap", DEFAULT_POLICY["chunk_overlap"]))
    except Exception:
        p["chunk_overlap"] = DEFAULT_POLICY["chunk_overlap"]
    try:
        p["chunk_size"] = int(p.get("chunk_size", DEFAULT_POLICY["chunk_size"]))
    except Exception:
        p["chunk_size"] = DEFAULT_POLICY["chunk_size"]
    return p

def _is_valid_span(span: Dict[str, Any]) -> bool:
    text = (span.get("text") or "").strip()
    label = (span.get("label") or "").upper()

    if not text:
        return False

    import re
    if re.fullmatch(r"[^\w\uAC00-\uD7A3]+", text):
        return False

    if label == "LC" and len(text) < 5:
        return False

    return True


@router.post("/extract")
async def extract_text(file: UploadFile):
    try:
        filename = (file.filename or "").lower()
        raw_bytes = await file.read()
        await file.seek(0)

        data = await extract_from_file(file)

        if filename.endswith(".pdf"):
            try:
                idx = pdf_module.extract_text_indexed(raw_bytes) or {}
                idx_text = idx.get("full_text")
                if isinstance(idx_text, str) and idx_text.strip():
                    data["full_text"] = idx_text
                    if isinstance(idx.get("pages"), list):
                        data["pages"] = idx["pages"]
            except Exception as e:
                logger.warning("PDF indexed text 생성 실패: %s", e)

            try:
                md_info = extract_pdf_markdown(raw_bytes)
                if md_info.get("markdown"):
                    data["markdown"] = md_info["markdown"]
                    if "pages" in md_info:
                        data["pages_md"] = [
                            {"page": p.get("page"), "markdown": p.get("markdown", "")}
                            for p in (md_info.get("pages") or [])
                        ]
            except Exception as e:
                logger.warning("PDF markdown 생성 실패: %s", e)

        # UI는 모든 확장자를 "Markdown"으로 렌더링한다.
        # - PDF는 markdown을 제공할 수 있음
        # - 그 외(또는 PDF에서도 markdown 생성 실패)는 full_text를 markdown으로 그대로 사용
        #   (형식을 임의로 변환하지 않기 때문에 정보 손실/추정이 없음)
        if isinstance(data, dict):
            md = data.get("markdown")
            if not isinstance(md, str) or not md.strip():
                ft = data.get("full_text")
                data["markdown"] = ft if isinstance(ft, str) else ""

        return data

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("텍스트 추출 중 오류: filename=%s", getattr(file, "filename", None))
        raise HTTPException(500, detail=str(e))


@router.get("/policy")
async def get_policy():
    return DEFAULT_POLICY


@router.put("/policy")
async def set_policy(policy: dict):
    return {"ok": True, "policy": policy}


@router.get("/rules")
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]


@router.post("/match")
async def match(req: dict):
    text = (req or {}).get("text", "") or ""
    return match_text(text)


@router.post("/detect")
async def detect(req: dict):
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = _effective_policy((req or {}).get("policy") or {})

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

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

    ner_spans: List[Dict[str, Any]] = []
    if run_ner_opt:
        ner_spans = run_ner(text=text, policy=policy, exclude_spans=regex_spans)
        for sp in ner_spans:
            sp["source"] = "ner"

    final_spans: List[Dict[str, Any]] = []
    for sp in (regex_spans + ner_spans):
        if not _is_valid_span(sp):
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


@router.post("/markdown")
async def extract_markdown_endpoint(file: UploadFile):
    filename = (file.filename or "").lower()
    raw_bytes = await file.read()

    # PDF는 pdf_module의 markdown을 사용
    if filename.endswith(".pdf"):
        return extract_pdf_markdown(raw_bytes)

    # 그 외: 모듈이 markdown을 제공하면 우선 사용, 없으면 full_text를 markdown으로 반환
    await file.seek(0)
    data = await extract_from_file(file)
    if not isinstance(data, dict):
        raise HTTPException(500, "extract_from_file 결과 형식이 올바르지 않습니다.")
    md = data.get("markdown")
    if isinstance(md, str) and md.strip():
        return {"markdown": md}
    ft = data.get("full_text")
    return {"markdown": ft if isinstance(ft, str) else ""}
