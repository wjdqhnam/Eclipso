from __future__ import annotations

import inspect
import json
import os
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile

from server.api.redaction_api import match_text
from server.modules import doc_module, hwp_module, pdf_module, ppt_module, xls_module
from server.modules.ner_module import run_ner  # 기존 틀 유지(미사용이어도 유지)
from server.modules.xml_redaction import xml_redact_to_file

router = APIRouter(prefix="/redact", tags=["redact"])


def _is_email_rule(rule_name: str) -> bool:
    return "email" in (rule_name or "").lower()


def _call_apply_text_redaction(pdf_bytes: bytes, spans: List[Dict[str, Any]]) -> bytes:
    fn = pdf_module.apply_text_redaction
    sig = inspect.signature(fn)

    if "patterns" in sig.parameters:
        if "extra_spans" in sig.parameters:
            return fn(pdf_bytes, extra_spans=spans, patterns=[])
        return fn(pdf_bytes, spans, [])

    old = getattr(pdf_module, "PRESET_PATTERNS", None)
    try:
        if old is not None:
            pdf_module.PRESET_PATTERNS = []
        if "extra_spans" in sig.parameters:
            return fn(pdf_bytes, extra_spans=spans)
        return fn(pdf_bytes, spans)
    finally:
        if old is not None:
            pdf_module.PRESET_PATTERNS = old


def _safe_load_json_list(s: Optional[str]) -> Optional[List[Any]]:
    if not s:
        return None
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, list) else None
    except Exception:
        return None


@router.post("/file", response_class=Response, summary="파일 레닥션")
async def redact_file(
    file: UploadFile = File(...),
    rules_json: Optional[str] = Form(None),
    ner_labels_json: Optional[str] = Form(None),
    ner_entities_json: Optional[str] = Form(None),
):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()
    encoded_fileName = file.filename.encode("utf-8", "ignore").decode("latin-1", "ignore")

    rules: Optional[List[str]] = None
    ner_allowed: Optional[List[str]] = None

    if rules_json:
        try:
            obj = json.loads(rules_json)
            if isinstance(obj, list):
                rules = [str(x).strip() for x in obj]
        except Exception:
            rules = None

    if ner_labels_json:
        try:
            obj = json.loads(ner_labels_json)
            if isinstance(obj, list):
                ner_allowed = [str(x) for x in obj]
        except Exception:
            ner_allowed = None

    client_entities = _safe_load_json_list(ner_entities_json)

    out: Optional[bytes] = None
    mime = "application/octet-stream"

    try:
        if ext == ".pdf":
            plain_result = pdf_module.extract_text(file_bytes) or {}
            plain_text = str(plain_result.get("full_text") or "")
            if not plain_text.strip():
                raise HTTPException(400, "PDF plain text가 비어 있습니다.")

            print(f"[PDF][DEBUG] plain_len={len(plain_text)} ner_allowed={ner_allowed}")

            # 1) 정규식 탐지 (plain text 기준)
            regex_result = match_text(plain_text)
            items = list(regex_result.get("items", []) or [])

            if isinstance(rules, list) and rules:
                allowed_lower: Set[str] = {str(x).strip().lower() for x in rules}
                items = [
                    it
                    for it in items
                    if str(it.get("rule") or it.get("name") or "").strip().lower() in allowed_lower
                ]

            regex_spans: List[Dict[str, Any]] = []
            for it in items:
                rule_name = str(it.get("rule") or it.get("name") or "")
                if it.get("valid") is False and not _is_email_rule(rule_name):
                    continue
                s, e = it.get("start"), it.get("end")
                if s is None or e is None:
                    continue
                s, e = int(s), int(e)
                if e > s:
                    regex_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": it.get("label") or rule_name or "REGEX",
                            "source": "regex",
                            "score": None,
                        }
                    )

            # 2) NER는 /ner/predict 기준으로만 생성
            ner_spans: List[Dict[str, Any]] = []
            allowed_set: Optional[Set[str]] = None
            if ner_allowed:
                allowed_set = {str(x).upper() for x in ner_allowed}

            if client_entities is not None:
                # UI가 /ner/predict entities를 보내면 그 결과를 그대로 사용
                for ent in client_entities:
                    if not isinstance(ent, dict):
                        continue
                    lab = str(ent.get("label") or "").upper()
                    s = ent.get("start")
                    e = ent.get("end")
                    if s is None or e is None:
                        continue
                    try:
                        s = int(s)
                        e = int(e)
                    except Exception:
                        continue
                    if e <= s:
                        continue
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue

                    ner_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": ent.get("score", None),
                        }
                    )

                print(f"[PDF][DEBUG] using client ner_entities={len(ner_spans)}")

            else:
                # UI가 entities를 안 보내도, 서버에서 /ner/predict와 동일하게 생성
                from server.api.ner_api import ner_predict_local, _auto_exclude_spans_by_regex

                exclude_spans = _auto_exclude_spans_by_regex(plain_text)
                labels = [str(x) for x in ner_allowed] if isinstance(ner_allowed, list) else None

                ents = ner_predict_local(
                    text=plain_text,
                    labels=labels,
                    exclude_spans=exclude_spans,
                )

                n = len(plain_text)
                for e in ents:
                    try:
                        s = max(0, min(n, int(e.get("start"))))
                        ed = max(0, min(n, int(e.get("end"))))
                    except Exception:
                        continue
                    if ed <= s:
                        continue

                    lab = str(e.get("label") or "").upper()
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue

                    ner_spans.append(
                        {
                            "start": s,
                            "end": ed,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": e.get("score", None),
                        }
                    )

                print(f"[PDF][DEBUG] server-side /ner/predict aligned ner_entities={len(ner_spans)}")

            # 3) regex 우선 병합 (겹치면 regex가 이김)
            used_ranges: List[Tuple[int, int]] = [(sp["start"], sp["end"]) for sp in regex_spans]

            ner_final: List[Dict[str, Any]] = []
            for sp in ner_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if s < 0 or e <= s:
                    continue
                if any(min(e, ue) > max(s, us) for us, ue in used_ranges):
                    continue
                ner_final.append(sp)
                used_ranges.append((s, e))

            final_spans = regex_spans + ner_final
            final_spans.sort(key=lambda x: (int(x["start"]), int(x["end"])))

            # 4) text 채우기
            enriched: List[Dict[str, Any]] = []
            for sp in final_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if e <= s or s >= len(plain_text):
                    continue
                s = max(0, s)
                e = min(len(plain_text), e)
                text = plain_text[s:e]
                if text.strip() == "":
                    continue
                enriched.append({**sp, "start": s, "end": e, "text": text})

            print(f"[PDF][DEBUG] enriched_spans={len(enriched)} sample={enriched[:3]}")

            out = _call_apply_text_redaction(file_bytes, enriched)
            mime = "application/pdf"

        elif ext in (".doc", ".hwp", ".ppt", ".xls"):
            module_map = {
                ".doc": doc_module,
                ".hwp": hwp_module,
                ".ppt": ppt_module,
                ".xls": xls_module,
            }
            out = module_map[ext].redact(file_bytes)

        elif ext in (".docx", ".pptx", ".xlsx", ".hwpx"):
            with tempfile.TemporaryDirectory() as tmpdir:
                src = os.path.join(tmpdir, f"src{ext}")
                dst = os.path.join(tmpdir, f"dst{ext}")
                with open(src, "wb") as f:
                    f.write(file_bytes)
                xml_redact_to_file(src, dst, file.filename)
                with open(dst, "rb") as f:
                    out = f.read()
            mime = "application/zip"

        else:
            raise HTTPException(400, f"지원하지 않는 포맷: {ext}")

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, f"{ext} 처리 중 오류: {e}")

    if not out:
        raise HTTPException(500, f"{ext} 레닥션 실패: 출력 없음")

    return Response(
        content=out,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{encoded_fileName}"'},
    )
