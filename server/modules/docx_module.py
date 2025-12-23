from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict, Any, Optional

# common 유틸 임포트: 상대 경로 우선, 실패 시 절대 경로 fallback
try:
    from .common import (
        cleanup_text,
        cleanup_text_keep_tabs,
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
        cleanup_text_keep_tabs,
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
    from ..core.schemas import XmlMatch, XmlLocation  # 현재 리포 구조
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation   # 옛 구조 호환
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  # 절대경로 fallback


def _local(tag: str) -> str:
    """XML 태그에서 로컬 네임만 추출: '{uri}p' -> 'p'"""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


# DOCX 텍스트 추출 (차트/임베디드 포함)
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


def _escape_html(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _cell_to_html(cell: str) -> str:
    # 셀 내부 줄바꿈은 <br>로 유지
    s = (cell or "").replace("\r\n", "\n").replace("\r", "\n")
    s = _escape_html(s).replace("\n", "<br/>")
    return s


def _rows_to_html_table(rows: List[List[str]]) -> str:
    if not rows:
        return ""
    w = max((len(r) for r in rows), default=0)
    rect = [list(r) + [""] * (w - len(r)) for r in rows]
    out: List[str] = []
    out.append("<table>")
    out.append("<tbody>")
    for r in rect:
        out.append("<tr>")
        for c in r:
            out.append(f"<td>{_cell_to_html(c)}</td>")
        out.append("</tr>")
    out.append("</tbody>")
    out.append("</table>")
    return "\n".join(out)


def _document_xml_to_blocks(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """
    word/document.xml을 문단/표 블록으로 파싱.
    - 표는 w:tbl/w:tr/w:tc 구조로 추출하여 2D rows로 유지
    - 셀 내부 줄바꿈(w:br, w:p 경계)은 그대로 보존
    """
    blocks: List[Dict[str, Any]] = []

    try:
        it = ET.iterparse(io.BytesIO(xml_bytes), events=("start", "end"))
    except Exception:
        # 파싱 실패 시: 텍스트만이라도 추출
        s = xml_bytes.decode("utf-8", "ignore")
        text_main = "".join(
            m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", s, re.DOTALL)
        )
        blocks.append({"type": "p", "text": cleanup_text(text_main)})
        return blocks

    in_tbl = 0
    in_tc = 0
    cur_p: List[str] = []
    cur_cell_lines: List[str] = []
    cur_row: List[str] = []
    cur_table: List[List[str]] = []

    def _flush_para_into_cell():
        nonlocal cur_p, cur_cell_lines
        txt = "".join(cur_p)
        txt = txt.replace("\r\n", "\n").replace("\r", "\n")
        txt = txt.strip("\n")
        if txt:
            cur_cell_lines.append(txt)
        cur_p = []

    def _flush_para_into_blocks():
        nonlocal cur_p, blocks
        txt = "".join(cur_p)
        txt = txt.replace("\r\n", "\n").replace("\r", "\n")
        txt = cleanup_text_keep_tabs(txt)
        if txt.strip():
            blocks.append({"type": "p", "text": txt})
        cur_p = []

    for ev, el in it:
        name = _local(el.tag).lower()

        if ev == "start":
            if name == "tbl":
                in_tbl += 1
                if in_tbl == 1:
                    cur_table = []
            elif name == "tr" and in_tbl:
                if in_tbl == 1:
                    cur_row = []
            elif name == "tc" and in_tbl:
                in_tc += 1
                if in_tbl == 1 and in_tc == 1:
                    cur_cell_lines = []
            elif name == "t":
                if el.text:
                    cur_p.append(el.text)
            elif name == "tab":
                cur_p.append("\t")
            elif name == "br":
                cur_p.append("\n")

        else:  # end
            if name == "p":
                if in_tbl and in_tc:
                    _flush_para_into_cell()
                else:
                    _flush_para_into_blocks()
            elif name == "tc" and in_tbl:
                # 셀 종료: 셀 내부 문단들을 줄바꿈으로 연결
                if in_tbl == 1 and in_tc == 1:
                    cell = "\n".join(cur_cell_lines).strip("\n")
                    cur_row.append(cell)
                in_tc = max(0, in_tc - 1)
            elif name == "tr" and in_tbl:
                if in_tbl == 1:
                    if cur_row:
                        cur_table.append(cur_row)
                cur_row = []
            elif name == "tbl":
                if in_tbl == 1:
                    if cur_table:
                        blocks.append({"type": "table", "rows": cur_table})
                in_tbl = max(0, in_tbl - 1)

            el.clear()

    # 남은 문단 flush(파싱 종료 시점)
    if cur_p:
        if in_tbl and in_tc:
            _flush_para_into_cell()
        else:
            _flush_para_into_blocks()

    return blocks


def _blocks_to_plain_text(blocks: List[Dict[str, Any]]) -> str:
    out: List[str] = []
    for b in blocks:
        if b.get("type") == "p":
            t = str(b.get("text") or "")
            if t.strip():
                out.append(t)
        elif b.get("type") == "table":
            rows = b.get("rows") or []
            if not isinstance(rows, list):
                continue
            for r in rows:
                if not isinstance(r, list):
                    continue
                out.append("\t".join(str(c or "") for c in r))
        out.append("")  # 블록 간 빈 줄
    return cleanup_text_keep_tabs("\n".join(out))


def _blocks_to_markdown(blocks: List[Dict[str, Any]]) -> str:
    out: List[str] = []
    for b in blocks:
        if b.get("type") == "p":
            t = str(b.get("text") or "").strip()
            if t:
                out.append(_escape_html(t))
                out.append("")  # 문단 분리
        elif b.get("type") == "table":
            rows = b.get("rows") or []
            if isinstance(rows, list) and rows:
                out.append(_rows_to_html_table(rows))  # raw HTML table
                out.append("")
    # 문단을 escape_html로 넣었기 때문에 HTML로 렌더링됨(줄바꿈은 marked breaks 옵션이 처리)
    return "\n".join(out).strip()


def docx_text(zipf: zipfile.ZipFile) -> str:
    # 본문(document.xml) - 평문(탐지용)
    try:
        xml_bytes = zipf.read("word/document.xml")
    except KeyError:
        xml_bytes = b""

    blocks = _document_xml_to_blocks(xml_bytes)
    text_main = _blocks_to_plain_text(blocks)

    # 차트 + 임베디드 XLSX
    text_charts = _collect_chart_texts(zipf)

    return cleanup_text_keep_tabs("\n".join(x for x in [text_main, text_charts] if x))


def docx_markdown(zipf: zipfile.ZipFile) -> str:
    try:
        xml_bytes = zipf.read("word/document.xml")
    except KeyError:
        xml_bytes = b""
    blocks = _document_xml_to_blocks(xml_bytes)
    md_main = _blocks_to_markdown(blocks)
    md_charts = _escape_html(_collect_chart_texts(zipf)) if _collect_chart_texts(zipf) else ""
    return "\n\n".join(x for x in [md_main, md_charts] if x).strip()


# /text/extract, /redactions/xml/scan 에서 사용하는 래퍼
def extract_text(file_bytes: bytes) -> dict:
    """
    DOCX 바이트에서 텍스트만 추출.
    full_text / pages 형식으로 반환 (HWPX extract_text와 동일 형식).
    """
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = docx_text(zipf)
        md = docx_markdown(zipf)

    return {
        "full_text": txt,
        "markdown": md if isinstance(md, str) else txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보 추출
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


# 파일 단위 레닥션: 각 파트별로 처리
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
