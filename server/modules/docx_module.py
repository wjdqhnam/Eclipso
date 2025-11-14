from __future__ import annotations

import io
import re
import zipfile
from typing import List, Tuple

# 공통 유틸/스키마
from .common import (
    cleanup_text,
    compile_rules,
    sub_text_nodes,
    chart_sanitize,
    xlsx_text_from_zip,
    redact_embedded_xlsx_bytes,
    sanitize_docx_content_types,
)
from server.core.schemas import XmlMatch, XmlLocation


# ─────────────────────
# 차트/임베디드 XLSX 텍스트 수집(후처리 정규화는 cleanup_text 일원화)
# ─────────────────────
def _collect_chart_texts(zipf: zipfile.ZipFile) -> str:
    parts: List[str] = []

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("word/charts/") and n.endswith(".xml")
    ):
        s = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s,
            re.I | re.DOTALL,
        ):
            text_part = m.group(1)
            num_part = m.group(2)
            v = (text_part or num_part or "").strip()
            if not v:
                continue
            # 순수 숫자만(축값/데이터 노이즈) 제외
            if num_part is not None and re.fullmatch(r"\d+(\.\d+)?", v):
                continue
            parts.append(v)

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("word/embeddings/") and n.lower().endswith(".xlsx")
    ):
        try:
            xlsx_bytes = zipf.read(name)
            with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as xzf:
                parts.append(xlsx_text_from_zip(xzf))
        except KeyError:
            pass
        except zipfile.BadZipFile:
            continue

    return cleanup_text("\n".join(p for p in parts if p))


# ─────────────────────
# DOCX 본문 텍스트 추출(문단 병합 + 차트 텍스트 결합 → cleanup_text 정규화)
# ─────────────────────
def docx_text(zipf: zipfile.ZipFile) -> str:
    try:
        xml = zipf.read("word/document.xml").decode("utf-8", "ignore")
    except KeyError:
        xml = ""

    lines: List[str] = []
    for p_xml in re.finditer(r"<w:p[^>]*>(.*?)</w:p>", xml, re.DOTALL):
        body = p_xml.group(1)
        text_in_p = "".join(
            m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", body, re.DOTALL)
        )
        text_in_p = cleanup_text(text_in_p)
        if text_in_p:
            lines.append(text_in_p)

    text_main = "\n".join(lines)
    text_charts = _collect_chart_texts(zipf)
    merged = cleanup_text("\n".join(x for x in [text_main, text_charts] if x))

    filtered_lines: List[str] = []
    for line in merged.splitlines():
        s = line.strip()
        if not s:
            continue
        if "<c:" in s:  # 잔여 차트 태그 라인 방지
            continue
        filtered_lines.append(line)

    return "\n".join(filtered_lines)


# ─────────────────────
# /text/extract 래퍼
# ─────────────────────
def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = docx_text(zipf)
    return {
        "full_text": txt,
        "pages": [{"page": 1, "text": txt}],
    }


# ─────────────────────
# 스캔(정규식 룰 → 후보 추출, cleanup_text 정규화 결과에 대해서만 수행)
# ─────────────────────
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = docx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                else:
                    continue
            else:
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
            if rx is None:
                continue
        except Exception:
            continue

        for m in rx.finditer(text):
            val = m.group(0)
            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=True,  # validator는 XML 레닥션 단계에서 적용
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(
                        kind="docx",
                        part="*merged_text*",
                        start=m.start(),
                        end=m.end(),
                    ),
                )
            )

    return out, "docx", text


# ─────────────────────
# 파일 단위 레닥션(DOCX 파트별 처리)
# ─────────────────────
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    if low == "[content_types].xml":
        return sanitize_docx_content_types(data)

    if low == "word/document.xml":
        return sub_text_nodes(data, comp)[0]

    if low.startswith("word/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    if low.startswith("word/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    return data
