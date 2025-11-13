from __future__ import annotations

import io
import re
import zipfile
from typing import List, Tuple

# common 유틸 임포트: 상대 경로 우선, 실패 시 절대 경로 fallback
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
except Exception:  # pragma: no cover
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

# schemas 임포트: core 우선, 실패 시 대안 경로 시도
try:
    from ..core.schemas import XmlMatch, XmlLocation  # 일반적인 현재 리포 구조
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation   # 일부 브랜치/옛 구조
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  # 절대경로 fallback


# ─────────────────────
# 차트/임베디드 XLSX 텍스트 수집 (차트 전용 필터만 적용)
# ─────────────────────
def _collect_chart_texts(zipf: zipfile.ZipFile, main_seen: set[str]) -> str:
    parts: List[str] = []

    # 1) 차트 XML 내부 라벨/값 텍스트
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("word/charts/") and n.endswith(".xml")
    ):
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s,
            re.I | re.DOTALL,
        ):
            text_part = m.group(1)
            num_part  = m.group(2)
            v = (text_part or num_part or "").strip()
            if not v:
                continue

            # 숫자 시리즈(정수/소수) → 노이즈
            if num_part is not None and re.fullmatch(r"\d+(\.\d+)?", v):
                continue

            parts.append(v)

    # 2) 임베디드 XLSX 내부 텍스트
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("word/embeddings/") and n.lower().endswith(".xlsx")
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

    # 라인 단위 정리 + 차트 전용 필터 + 본문과의 중복 제거 + 차트 내부 중복 제거
    filtered: List[str] = []
    seen_chart: set[str] = set()

    for line in cleanup_text("\n".join(parts)).splitlines():
        s = line.strip()
        if not s:
            continue
        if "<c:" in s:  # 차트 태그 조각 제거
            continue
        if re.fullmatch(r"항목\s*\d+", s):  # 라벨 제거
            continue
        if re.fullmatch(r"계열\s*\d+", s):  # 라벨 제거
            continue
        # 본문(document.xml)에서 이미 나온 줄과 중복이면 스킵 (본문 유지, 차트만 제거)
        if s in main_seen:
            continue
        # 차트 내부에서도 같은 줄 중복되면 한 번만
        if s in seen_chart:
            continue
        seen_chart.add(s)
        filtered.append(s)

    return "\n".join(filtered)


# ─────────────────────
# DOCX 본문 텍스트 추출 (본문은 그대로, 줄바꿈 유지 / 차트는 위 로직으로만 후처리)
# ─────────────────────
def docx_text(zipf: zipfile.ZipFile) -> str:
    # 본문(document.xml)
    try:
        xml = zipf.read("word/document.xml").decode("utf-8", "ignore")
    except KeyError:
        xml = ""

    # 1) 문단(<w:p>...</w:p>) 단위로 텍스트를 모아 줄바꿈 유지
    main_lines: List[str] = []
    for p_xml in re.finditer(r"<w:p[^>]*>(.*?)</w:p>", xml, re.DOTALL):
        body = p_xml.group(1)
        text_in_p = "".join(
            m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", body, re.DOTALL)
        )
        text_in_p = cleanup_text(text_in_p)
        if text_in_p:
            main_lines.append(text_in_p)

    # 본문은 중복 제거하지 않음(요청사항)
    main_text = "\n".join(main_lines)
    main_seen = {ln.strip() for ln in main_lines if ln.strip()}

    # 2) 차트 + 임베디드 XLSX 텍스트(본문과의 중복만 제거, 차트 내부 중복 제거)
    chart_text = _collect_chart_texts(zipf, main_seen)

    # 3) 합치고 한 번 더 가볍게 정리
    merged = "\n".join([main_text, chart_text] if chart_text else [main_text])
    merged = cleanup_text(merged)

    return merged


# /text/extract, /redactions/xml/scan 에서 사용하는 래퍼
def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = docx_text(zipf)
    return {
        "full_text": txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


# ─────────────────────
# 스캔: 정규식 규칙으로 DOCX 텍스트에서 민감정보 후보를 추출
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
                    valid=True,  # validator는 레닥션 단계에서 적용
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
# 파일 단위 레닥션: 각 파트별 처리
# ─────────────────────
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 0) DOCX 루트 컨텐츠 타입 정리
    if low == "[content_types].xml":
        return sanitize_docx_content_types(data)

    # 1) 본문 XML: 텍스트 노드만 마스킹
    if low == "word/document.xml":
        return sub_text_nodes(data, comp)[0]

    # 2) 차트 XML: 텍스트 노드 마스킹 후 다시 한 번 텍스트만
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
