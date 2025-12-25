from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Tuple


def _escape_html(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _cell_to_html(cell: str) -> str:
    # 셀 내부 줄바꿈은 <br>로 유지
    s = (cell or "").replace("\r\n", "\n").replace("\r", "\n")
    s = _escape_html(s)
    s = s.replace("\n", "<br/>")
    return s


def _rows_to_html_table(rows: List[List[str]]) -> str:
    if not rows:
        return ""
    # 직사각형 보정
    w = max((len(r) for r in rows), default=0)
    rect = [list(r) + [""] * (w - len(r)) for r in rows]
    body = []
    body.append('<table>')
    body.append("<tbody>")
    for r in rect:
        body.append("<tr>")
        for c in r:
            body.append(f"<td>{_cell_to_html(c)}</td>")
        body.append("</tr>")
    body.append("</tbody>")
    body.append("</table>")
    return "\n".join(body)


def _extract_html_table_like(root: ET.Element) -> Optional[str]:
    # 1) HTML-ish: <table><tr><td>
    rows: List[List[str]] = []
    found = False
    for tbl in root.iter():
        if _local(tbl.tag).lower() != "table":
            continue
        found = True
        rows = []
        for tr in list(tbl):
            if _local(tr.tag).lower() != "tr":
                continue
            row: List[str] = []
            for td in list(tr):
                if _local(td.tag).lower() not in ("td", "th"):
                    continue
                txt = "".join(td.itertext())
                row.append(txt)
            if row:
                rows.append(row)
        if rows:
            return _rows_to_html_table(rows)
    return _rows_to_html_table(rows) if found and rows else None


def _extract_wordprocessingml_table(root: ET.Element) -> Optional[str]:
    # 2) WordprocessingML: w:tbl / w:tr / w:tc
    # Namespace를 몰라도 local-name으로 처리
    out_tables: List[str] = []
    for tbl in root.iter():
        if _local(tbl.tag).lower() != "tbl":
            continue
        rows: List[List[str]] = []
        for tr in tbl:
            if _local(tr.tag).lower() != "tr":
                continue
            row: List[str] = []
            for tc in tr:
                if _local(tc.tag).lower() != "tc":
                    continue
                # tc 안의 텍스트를 문단 경계로 줄바꿈 유지
                parts: List[str] = []
                for p in tc.iter():
                    if _local(p.tag).lower() == "p":
                        t = "".join(p.itertext()).strip()
                        if t:
                            parts.append(t)
                cell = "\n".join(parts) if parts else "".join(tc.itertext())
                row.append(cell)
            if row:
                rows.append(row)
        if rows:
            out_tables.append(_rows_to_html_table(rows))
    if out_tables:
        return "\n\n".join(out_tables)
    return None


def extract_text(file_bytes: bytes) -> Dict[str, Any]:
    # UTF-8 우선, 실패 시 유니코드 대체
    try:
        s = file_bytes.decode("utf-8")
    except Exception:
        s = file_bytes.decode("utf-8", "ignore")

    # 파싱 실패 대비: 최소한 줄바꿈은 살린다
    full_text_fallback = re.sub(r"\r\n?", "\n", s)

    try:
        # BOM/앞 공백 등으로 iterparse가 민감할 수 있어 fromstring으로 처리
        root = ET.fromstring(s)
    except Exception:
        return {"full_text": full_text_fallback.strip(), "markdown": full_text_fallback.strip(), "pages": [{"page": 1, "text": full_text_fallback.strip()}]}

    table_html = _extract_html_table_like(root) or _extract_wordprocessingml_table(root)
    full_text = "\n".join(line for line in ("".join(root.itertext())).splitlines())
    full_text = full_text.strip()

    if table_html:
        md = table_html
    else:
        md = full_text if full_text else full_text_fallback.strip()

    return {
        "full_text": full_text if full_text else full_text_fallback.strip(),
        "markdown": md,
        "pages": [{"page": 1, "text": full_text if full_text else full_text_fallback.strip()}],
    }


