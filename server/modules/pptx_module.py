from __future__ import annotations

import io
import re
import zipfile
from typing import List, Tuple

# ── common 유틸 임포트: 상대 경로 우선, 실패 시 절대 경로 fallback ────────────────
try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )
except Exception: 
    from server.modules.common import ( 
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )


from server.core.schemas import XmlMatch, XmlLocation

def _collect_chart_and_embedded_texts(zipf: zipfile.ZipFile) -> str:
    parts: List[str] = []

    # 1) 차트 XML 텍스트 수집
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/charts/") and n.endswith(".xml")
    ):
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s,
            re.IGNORECASE | re.DOTALL,
        ):
            text_part = m.group(1)
            num_part = m.group(2)
            v = (text_part or num_part or "").strip()
            if not v:
                continue
            parts.append(v)

    # 2) 임베디드 XLSX (차트 데이터 등)
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/embeddings/") and n.lower().endswith(".xlsx")
    ):
        try:
            xlsx_bytes = zipf.read(name)
        except KeyError:
            continue

        try:
            with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as xzf:
                parts.append(xlsx_text_from_zip(xzf))
        except zipfile.BadZipFile:
            continue

    return cleanup_text("\n".join(p for p in parts if p))


def pptx_text(zipf: zipfile.ZipFile) -> str:
    all_txt: List[str] = []

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/slides/") and n.endswith(".xml")
    ):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        all_txt += [
            m.group(1)
            for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)
            if (m.group(1) or "").strip()
        ]

    chart_txt = _collect_chart_and_embedded_texts(zipf)
    if chart_txt:
        all_txt.append(chart_txt)

    return cleanup_text("\n".join(all_txt))


# ────────────────────────────────────────────────────
# /text/extract, /redactions/xml/scan 에서 사용하는 래퍼
# ────────────────────────────────────────────────────
def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = pptx_text(zipf)

    return {
        "full_text": txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


# ────────────────────────────────────────────────────
# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보를 추출
# ────────────────────────────────────────────────────
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = pptx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 5:
                    rule_name, rx, need_valid, _prio, validator = (
                        ent[0],
                        ent[1],
                        bool(ent[2]),
                        ent[3],
                        ent[4],
                    )
                elif len(ent) >= 3:
                    rule_name, rx, need_valid = ent[0], ent[1], bool(ent[2])
                    validator = None
                elif len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                    need_valid, validator = True, None
                else:
                    continue
            else:
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
                need_valid = bool(getattr(ent, "need_valid", True))
                validator = getattr(ent, "validator", None)

            if rx is None:
                continue
        except Exception:
            continue

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and callable(validator):
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False

            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(
                        kind="pptx",
                        part="*merged_text*",
                        start=m.start(),
                        end=m.end(),
                    ),
                )
            )

    return out, "pptx", text


# ────────────────────────────────────────────────────
# 파일 단위 레닥션: 슬라이드/차트/임베디드 XLSX 처리
# ────────────────────────────────────────────────────
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    if low.startswith("ppt/slides/") and low.endswith(".xml"):
        b, _ = sub_text_nodes(data, comp)
        return b

    if low.startswith("ppt/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        b3, _ = sub_text_nodes(b2, comp)
        return b3

    if low.startswith("ppt/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    return data
