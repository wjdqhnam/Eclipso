from __future__ import annotations

import inspect
import json
import os
import tempfile
import traceback
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import fitz
from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile

from server.api.redaction_api import match_text
from server.modules import doc_module, hwp_module, pdf_module, ppt_module, xls_module
from server.modules.ner_module import run_ner
from server.modules.xml_redaction import xml_redact_to_file

router = APIRouter(prefix="/redact", tags=["redact"])

_JOIN_NEWLINE_RE = re.compile(r"([\w\uAC00-\uD7A3.%+\-/])\n([\w\uAC00-\uD7A3.%+\-/])")


def _join_broken_lines(text: str | None) -> str:
    if not text:
        return ""
    prev, t = None, text.replace("\r\n", "\n")
    while prev != t:
        prev = t
        t = _JOIN_NEWLINE_RE.sub(r"\1\2", t)
    return t


def _build_index_map(orig: str, norm: str) -> List[int]:
    mapping, oi = [], 0
    for c in norm:
        while oi < len(orig) and orig[oi].isspace() and not c.isspace():
            oi += 1
        mapping.append(min(oi, len(orig) - 1))
        if oi < len(orig):
            oi += 1
    return mapping


def _map_spans_back(spans: List[Dict[str, Any]], mapping: List[int]) -> List[Dict[str, Any]]:
    out = []
    for sp in spans:
        s, e = int(sp.get("start", 0)), int(sp.get("end", 0))
        if s >= len(mapping) or e > len(mapping):
            continue
        out.append({**sp, "start": mapping[s], "end": mapping[e - 1] + 1})
    return out


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


@router.post("/file", response_class=Response, summary="파일 레닥션")
async def redact_file(
    file: UploadFile = File(...),
    rules_json: Optional[str] = Form(None),
    ner_labels_json: Optional[str] = Form(None),
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
                rules = [str(x) for x in obj]
        except Exception:
            rules = None

    if ner_labels_json:
        try:
            obj = json.loads(ner_labels_json)
            if isinstance(obj, list):
                ner_allowed = [str(x) for x in obj]
        except Exception:
            ner_allowed = None

    out: Optional[bytes] = None
    mime = "application/octet-stream"

    try:
        if ext == ".doc":
            out = doc_module.redact(file_bytes)
            mime = "application/msword"

        elif ext == ".hwp":
            out = hwp_module.redact(file_bytes)
            mime = "application/x-hwp"

        elif ext == ".ppt":
            out = ppt_module.redact(file_bytes)
            mime = "application/vnd.ms-powerpoint"

        elif ext == ".xls":
            out = xls_module.redact(file_bytes)
            mime = "application/vnd.ms-excel"

        elif ext == ".pdf":
            # UI와 동일한 기준으로 탐지: get_text("text") 대신 extract_markdown() 결과를 사용
            try:
                md_result = pdf_module.extract_markdown(file_bytes, by_page=True) or {}
                pages_md = list(md_result.get("pages") or [])

                if pages_md:
                    parts: List[str] = []
                    page_ranges: List[Tuple[int, int, int]] = []  # (page_no, start, end) in orig markdown
                    offset = 0
                    for p in pages_md:
                        page_no = int(p.get("page") or 0) or (len(page_ranges) + 1)
                        md = str(p.get("markdown") or "")

                        if parts:
                            parts.append("\n\n")
                            offset += 2

                        start_off = offset
                        parts.append(md)
                        offset += len(md)
                        end_off = offset
                        page_ranges.append((page_no, start_off, end_off))

                    text = "".join(parts)
                else:
                    text = str(md_result.get("markdown") or "")
                    page_ranges = []
            except Exception:
                raise HTTPException(400, "PDF 마크다운 추출 실패")

            if not text.strip():
                raise HTTPException(400, "PDF 본문이 비어 있습니다.")

            def _page_hint(page_ranges_: List[Tuple[int, int, int]], orig_idx: int) -> Optional[int]:
                for (pno, s0, e0) in page_ranges_:
                    if s0 <= orig_idx < e0:
                        return int(pno)
                return None

            # 줄/블록 분리(특히 이메일) 대응: 탐지는 줄바꿈 결합 텍스트로 수행
            norm_text = _join_broken_lines(text)
            index_map = _build_index_map(text, norm_text)

            # --- DEBUG ---
            print(f"[PDF][DEBUG] orig_md_len={len(text)} norm_text_len={len(norm_text)} rules={rules} ner_allowed={ner_allowed}")

            # 정규식 탐지 (정규화된 텍스트 기준)
            regex_result = match_text(norm_text)
            items = list(regex_result.get("items", []) or [])
            print(f"[PDF][DEBUG] regex_raw_items={len(items)} counts={regex_result.get('counts')}")

            # rules_json 필터 (대소문자/표기 흔들림 방지)
            if isinstance(rules, list) and rules:
                allowed_lower: Set[str] = {str(x).strip().lower() for x in rules}
                before = len(items)
                items = [
                    it
                    for it in items
                    if str(it.get("rule") or it.get("name") or "").strip().lower() in allowed_lower
                ]
                print(f"[PDF][DEBUG] regex_after_filter={len(items)} (before={before}) allowed_lower={sorted(allowed_lower)}")

            # regex_spans 생성 (norm 기준)
            regex_spans: List[Dict[str, Any]] = []
            for it in items:
                rule_name = str(it.get("rule") or it.get("name") or "")
                if it.get("valid") is False and not _is_email_rule(rule_name):
                    continue
                s, e = it.get("start"), it.get("end")
                if s is None or e is None:
                    continue
                s = int(s); e = int(e)
                if e <= s:
                    continue
                label = it.get("label") or rule_name or "REGEX"
                regex_spans.append(
                    {
                        "start": s,
                        "end": e,
                        "label": str(label),
                        "source": "regex",
                        "score": None,
                    }
                )

            print(f"[PDF][DEBUG] regex_spans={len(regex_spans)} sample={regex_spans[:2]}")

            # 정규식 구간 마스킹 → NER 입력용 (정규식 구간은 NER에서 다시 잡히지 않게)
            masked_norm = norm_text
            if regex_spans:
                chars = list(norm_text)
                for sp in regex_spans:
                    s = max(0, int(sp["start"]))
                    e = min(len(chars), int(sp["end"]))
                    for i in range(s, e):
                        if chars[i] != "\n":
                            chars[i] = " "
                masked_norm = "".join(chars)

            policy = {
                "chunk_size": 1500,
                "chunk_overlap": 200,
                "allowed_labels": ner_allowed or ["PS", "LC", "OG", "DT"],
                "raise_on_error": True,
            }

            ner_spans = run_ner(masked_norm, policy=policy)
            one = [sp for sp in ner_spans if len((sp.get("text") or "").strip()) == 1]
            print(f"[PDF1][DEBUG] ner_1char={len(one)} sample={one[:10]}")
            print(f"[PDF][DEBUG] ner_spans_raw={len(ner_spans)} sample={ner_spans[:2]}")

            # 병합 (regex 우선, overlap은 NER 제거) - norm 기준
            used_ranges: List[Tuple[int, int]] = []
            for sp in regex_spans:
                s = int(sp.get("start", 0) or 0)
                e = int(sp.get("end", 0) or 0)
                if e > s:
                    used_ranges.append((s, e))

            ner_final: List[Dict[str, Any]] = []
            for sp in ner_spans:
                s = int(sp.get("start", 0) or 0)
                e = int(sp.get("end", 0) or 0)
                if e <= s:
                    continue
                if any(min(e, ue) > max(s, us) for (us, ue) in used_ranges):
                    continue
                ner_final.append(sp)
                used_ranges.append((s, e))

            final_spans = regex_spans + ner_final
            final_spans.sort(key=lambda x: (int(x.get("start", 0)), int(x.get("end", 0))))
            print(f"[PDF][DEBUG] final_spans_norm={len(final_spans)}")

            # UI 마크다운 원문 기준으로 text/page를 채워서 PDF 마스킹 검색에 활용
            enriched: List[Dict[str, Any]] = []
            for sp in final_spans:
                s = int(sp.get("start", 0) or 0)
                e = int(sp.get("end", 0) or 0)
                if e <= s:
                    continue
                if s >= len(index_map) or e > len(index_map):
                    continue

                os_ = int(index_map[s])
                oe_ = int(index_map[e - 1]) + 1
                os_ = max(0, min(os_, len(text)))
                oe_ = max(0, min(oe_, len(text)))

                span_text = text[os_:oe_]
                if not span_text.strip():
                    # 최후 fallback: 값 기반(정규식) 또는 norm substring
                    span_text = sp.get("text") or norm_text[s:e] or ""

                page_hint = _page_hint(page_ranges, os_) if page_ranges else None

                out_sp = dict(sp)
                out_sp["text"] = span_text
                if page_hint is not None:
                    out_sp["page"] = int(page_hint)
                enriched.append(out_sp)

            print(f"[PDF][DEBUG] enriched_spans={len(enriched)} sample={enriched[:2]}")

            out = _call_apply_text_redaction(file_bytes, enriched)
            mime = "application/pdf"


        elif ext in (".docx", ".pptx", ".xlsx", ".hwpx"):
            with tempfile.TemporaryDirectory() as tmpdir:
                src_path = os.path.join(tmpdir, f"src{ext}")
                dst_path = os.path.join(tmpdir, f"dst{ext}")
                with open(src_path, "wb") as f:
                    f.write(file_bytes)
                xml_redact_to_file(src_path, dst_path, file.filename)
                with open(dst_path, "rb") as f:
                    out = f.read()
            mime = "application/zip"

        else:
            raise HTTPException(400, f"지원하지 않는 포맷: {ext}")

    except HTTPException:
        raise
    except Exception as e:
        print("[레닥션 오류 발생]")
        traceback.print_exc()
        raise HTTPException(500, f"{ext} 처리 중 오류: {e}")

    if not out:
        raise HTTPException(500, f"{ext} 레닥션 실패: 출력 없음")

    return Response(
        content=out,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{encoded_fileName}"'},
    )
