# server/modules/docx_module.py
# -*- coding: utf-8 -*-
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
        chart_rels_sanitize,
        sanitize_docx_content_types,
    )
except Exception:  # pragma: no cover - 구조가 달라졌을 때 대비
    from server.modules.common import (  # type: ignore
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
        chart_rels_sanitize,
        sanitize_docx_content_types,
    )

# ── schemas 임포트: core 우선, 실패 시 대안 경로 시도 ─────────────────────────
try:
    from ..core.schemas import XmlMatch, XmlLocation  # 현재 리포 구조
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation   # 옛 구조 호환
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  # 절대경로 fallback


# ─────────────────────────────────────────────────────────────────────────────
# DOCX 텍스트 추출
#   - word/document.xml 본문 텍스트
#   - word/charts/*.xml 라벨/값
#   - word/embeddings/*.xlsx 안의 셀/차트 텍스트
# ─────────────────────────────────────────────────────────────────────────────
def _collect_chart_texts(zipf: zipfile.ZipFile) -> str:
    parts: List[str] = []

    # 1) 차트 XML 내부 라벨/캐시 텍스트
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("word/charts/") and n.endswith(".xml")
    ):
        s = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I | re.DOTALL
        ):
            v = (m.group(1) or m.group(2) or "")
            if v:
                parts.append(v)

    # 2) 임베디드 XLSX 내부의 문자열/시트/차트 텍스트
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


def docx_text(zipf: zipfile.ZipFile) -> str:
    # 본문(document.xml)
    try:
        xml = zipf.read("word/document.xml").decode("utf-8", "ignore")
    except KeyError:
        xml = ""

    text_main = "".join(
        m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL)
    )
    text_main = cleanup_text(text_main)

    # 차트 + 임베디드 XLSX
    text_charts = _collect_chart_texts(zipf)

    return cleanup_text("\n".join(x for x in [text_main, text_charts] if x))


# ★ /text/extract, /redactions/xml/scan 에서 사용하는 래퍼
def extract_text(file_bytes: bytes) -> dict:
    """
    DOCX 바이트에서 텍스트만 추출.
    full_text / pages 형식으로 반환 (HWPX extract_text와 동일 형식).
    """
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = docx_text(zipf)

    return {
        "full_text": txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보 추출
#   - compile_rules()가 3/4/5튜플 또는 네임드 객체여도 동작하게 유연하게 처리
# ─────────────────────────────────────────────────────────────────────────────
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = docx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            # tuple/list 계열
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                else:
                    continue
            else:
                # 네임드 객체(SimpleNamespace 등)
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
                    valid=True,  # DOCX 스캔은 일단 전부 valid로 표시 (레닥션 쪽에서 validator 사용)
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


# ─────────────────────────────────────────────────────────────────────────────
# 파일 단위 레닥션: 각 파트별로 처리
# ─────────────────────────────────────────────────────────────────────────────
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 0) DOCX 루트 컨텐츠 타입 정리
    if low == "[content_types].xml":
        return sanitize_docx_content_types(data)

    # 1) 본문 XML: 텍스트 노드만 마스킹
    if low == "word/document.xml":
        return sub_text_nodes(data, comp)[0]

    # 2) 차트 XML: 라벨/캐시 + 텍스트 노드 마스킹
    if low.startswith("word/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    # 3) 차트 RELS
    if low.startswith("word/charts/_rels/") and low.endswith(".rels"):
        b2, _ = chart_rels_sanitize(data)
        return b2

    # 4) 임베디드 XLSX
    if low.startswith("word/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    # 5) 기타 파트는 그대로
    return data
