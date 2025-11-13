from __future__ import annotations

import io
import re
import zipfile
from typing import List, Tuple

# 공통 유틸
try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        chart_rels_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )
except Exception: 
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        chart_rels_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )

# schemas 임포트 (core 우선)
try:
    from ..core.schemas import XmlMatch, XmlLocation
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation 
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  


def _collect_chart_and_embedded_texts(zipf: zipfile.ZipFile) -> str:
    parts: List[str] = []

    # 차트 XML: <a:t>, <c:v> 안의 텍스트만 추출
    for name in sorted(
        n
        for n in zipf.namelist()
        if n.startswith("ppt/charts/") and n.endswith(".xml")
    ):
        s = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s,
            re.I | re.DOTALL,
        ):
            v = (m.group(1) or m.group(2) or "")
            if v:
                parts.append(v)

    # 임베디드 XLSX (ppt/embeddings/*.xlsx)
    for name in sorted(
        n
        for n in zipf.namelist()
        if n.startswith("ppt/embeddings/") and n.lower().endswith(".xlsx")
    ):
        try:
            xlsx_bytes = zipf.read(name)
            with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as xzf:
                parts.append(xlsx_text_from_zip(xzf))
        except KeyError:
            continue
        except zipfile.BadZipFile:
            continue

    return cleanup_text("\n".join(p for p in parts if p))


def pptx_text(zipf: zipfile.ZipFile) -> str:
    all_txt: List[str] = []

    # 슬라이드 본문
    for name in sorted(
        n
        for n in zipf.namelist()
        if n.startswith("ppt/slides/") and n.endswith(".xml")
    ):
        xml = zipf.read(name).decode("utf-8", "ignore")
        all_txt += [
            tm.group(1)
            for tm in re.finditer(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)
        ]

    # 차트 + 임베디드 XLSX
    chart_txt = _collect_chart_and_embedded_texts(zipf)
    if chart_txt:
        all_txt.append(chart_txt)

    text = cleanup_text("\n".join(all_txt))

    # 시트 참조(Sheet1!$B$1, Sheet1!$B$2:$B$5 등) 제거
    text = re.sub(
        r"[A-Za-z0-9_]+!\$[A-Z]{1,3}\$\d+(?::\$[A-Z]{1,3}\$\d+)?",
        "",
        text,
    )
    text = re.sub(r"\b\d+\.\d{10,}\b", "", text)
    text = text.replace("General", "")
    text = re.sub(r"<[^>]+>", "", text)

    return cleanup_text(text)


def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = pptx_text(zipf)

    return {
        "full_text": txt,
        "pages": [{"page": 1, "text": txt}],
    }


def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = pptx_text(zipf)
    comp = compile_rules()

    matches: List[XmlMatch] = []
    debug_info: List[str] = []

    for rule_name, cfg in comp.items():
        pattern = cfg["pattern"]
        validator = cfg["validator"]
        ensure_valid = cfg["ensure_valid"]

        for m in pattern.finditer(text):
            val = m.group(0)
            ok = True

            if validator is not None:
                valid, reason = validator(val)
                if not valid:
                    debug_info.append(
                        f"[pptx] rule={rule_name} value={val} invalid: {reason}"
                    )
                    if ensure_valid:
                        ok = False

            matches.append(
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

    debug_str = "\n".join(debug_info)
    return matches, text, debug_str


def redact_part_bytes(name: str, data: bytes, comp) -> bytes:
    low = name.lower()

    # 슬라이드 XML
    if low.startswith("ppt/slides/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    # 차트 XML
    if low.startswith("ppt/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    # 차트 rels
    if low.startswith("ppt/charts/_rels/") and low.endswith(".rels"):
        b3, _ = chart_rels_sanitize(data)
        return b3

    # 임베디드 XLSX
    if low.startswith("ppt/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    # 그 외는 그대로
    return data


def redact_item(name: str, data: bytes, comp) -> bytes:
    # xml_redaction.xml_redact_to_file 에서 호출하는 호환 래퍼
    return redact_part_bytes(name, data, comp)
