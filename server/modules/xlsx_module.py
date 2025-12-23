from __future__ import annotations
import io, zipfile
import re
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
        chart_rels_sanitize,
    )
except Exception:  # pragma: no cover - 패키지 구조 달라졌을 때 대비
    from server.modules.common import (  # type: ignore
        cleanup_text,
        cleanup_text_keep_tabs,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        chart_rels_sanitize,
    )

#  schemas 임포트: core 우선, 실패 시 대안 경로 시도
try:
    from ..core.schemas import XmlMatch, XmlLocation  # 일반적인 현재 리포 구조
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation   # 일부 브랜치/옛 구조
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  # 절대경로 fallback


# RULES(validator) 접근
try:
    from ..core.redaction_rules import RULES
except Exception:
    try:
        from ..redaction_rules import RULES  # type: ignore
    except Exception:
        from server.core.redaction_rules import RULES  # type: ignore


def xlsx_text(zipf: zipfile.ZipFile) -> str:
    """XLSX(zip)에서 텍스트를 모아 하나의 문자열로 합칩니다."""
    return xlsx_text_from_zip(zipf)


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
    s = (cell or "").replace("\r\n", "\n").replace("\r", "\n")
    return _escape_html(s).replace("\n", "<br/>")


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


def _col_letters_to_index(col: str) -> int:
    col = col.upper()
    n = 0
    for ch in col:
        if "A" <= ch <= "Z":
            n = n * 26 + (ord(ch) - ord("A") + 1)
    return n


def _split_cell_ref(r: str) -> Tuple[int, int]:
    # "BC12" -> (row=12, col=55)
    m = re.match(r"^([A-Za-z]+)(\d+)$", str(r or ""))
    if not m:
        return (0, 0)
    col = _col_letters_to_index(m.group(1))
    row = int(m.group(2))
    return (row, col)


def _read_shared_strings(zipf: zipfile.ZipFile) -> List[str]:
    try:
        xml = zipf.read("xl/sharedStrings.xml")
    except Exception:
        return []
    try:
        root = ET.fromstring(xml)
    except Exception:
        return []
    out: List[str] = []
    for si in root.findall(".//{*}si"):
        # si 안의 모든 t 텍스트를 이어붙임(서식 run 포함)
        parts: List[str] = []
        for t in si.findall(".//{*}t"):
            if t.text:
                parts.append(t.text)
        out.append("".join(parts))
    return out


def _sheet_names(zipf: zipfile.ZipFile) -> Dict[str, str]:
    """
    sheet xml path -> sheet name
    """
    try:
        wb = zipf.read("xl/workbook.xml")
    except Exception:
        return {}
    try:
        root = ET.fromstring(wb)
    except Exception:
        return {}

    # r:id -> name
    rid_to_name: Dict[str, str] = {}
    for sh in root.findall(".//{*}sheets/{*}sheet"):
        name = sh.attrib.get("name") or ""
        rid = sh.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id") or sh.attrib.get("r:id") or ""
        if rid:
            rid_to_name[rid] = name

    # rels: r:id -> target
    try:
        rels = zipf.read("xl/_rels/workbook.xml.rels")
        relroot = ET.fromstring(rels)
    except Exception:
        return {}

    path_to_name: Dict[str, str] = {}
    for rel in relroot.findall(".//{*}Relationship"):
        rid = rel.attrib.get("Id") or ""
        target = rel.attrib.get("Target") or ""
        if not rid or not target:
            continue
        if rid not in rid_to_name:
            continue
        # Target은 상대 경로("worksheets/sheet1.xml")
        path = "xl/" + target.lstrip("/")
        path_to_name[path] = rid_to_name[rid]
    return path_to_name


def xlsx_markdown_tables(zipf: zipfile.ZipFile, max_rows: int = 200, max_cols: int = 50) -> str:
    sst = _read_shared_strings(zipf)
    path_to_name = _sheet_names(zipf)

    sheets = sorted([n for n in zipf.namelist() if n.startswith("xl/worksheets/") and n.endswith(".xml")])
    out: List[str] = []

    for path in sheets:
        try:
            root = ET.fromstring(zipf.read(path))
        except Exception:
            continue

        # row -> col -> value
        grid: Dict[int, Dict[int, str]] = {}
        max_r = 0
        max_c = 0

        for c in root.findall(".//{*}c"):
            ref = c.attrib.get("r") or ""
            r_i, c_i = _split_cell_ref(ref)
            if r_i <= 0 or c_i <= 0:
                continue
            if r_i > max_rows or c_i > max_cols:
                continue

            t = c.attrib.get("t") or ""
            v = ""
            if t == "s":
                vv = c.find("{*}v")
                if vv is not None and vv.text and vv.text.strip().isdigit():
                    idx = int(vv.text.strip())
                    if 0 <= idx < len(sst):
                        v = sst[idx]
            elif t == "inlineStr":
                tt = c.find(".//{*}is/{*}t")
                if tt is not None and tt.text:
                    v = tt.text
            else:
                vv = c.find("{*}v")
                if vv is not None and vv.text:
                    v = vv.text

            if v is None:
                continue
            v = str(v)
            if not v and not v.strip():
                continue

            grid.setdefault(r_i, {})[c_i] = v
            max_r = max(max_r, r_i)
            max_c = max(max_c, c_i)

        if not grid:
            continue

        rows: List[List[str]] = []
        for r_i in range(1, max_r + 1):
            row: List[str] = []
            for c_i in range(1, max_c + 1):
                row.append(grid.get(r_i, {}).get(c_i, ""))
            # 완전 빈 행은 스킵
            if any(x.strip() for x in row):
                rows.append(row)

        if not rows:
            continue

        name = path_to_name.get(path) or path.split("/")[-1]
        out.append(f"**Sheet: {_escape_html(name)}**")
        out.append(_rows_to_html_table(rows))
        out.append("")

    return "\n\n".join(out).strip()


# /text/extract, /redactions/xml/scan 에서 사용하는 래퍼
def extract_text(file_bytes: bytes) -> dict:
    """바이트로 들어온 XLSX에서 텍스트만 추출."""
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        # 탐지용 평문
        txt = cleanup_text_keep_tabs(xlsx_text(zipf))
        # 뷰어용 markdown(표 레이아웃 보존)
        md = xlsx_markdown_tables(zipf)
    return {
        "full_text": txt,
        "markdown": md if isinstance(md, str) and md.strip() else txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


def _get_validator(rule_name: str):
    v = None
    try:
        v = RULES.get(rule_name, {}).get("validator")
    except Exception:
        v = None
    return v if callable(v) else None


# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보를 추출
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            # tuple/list 계열
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 3:
                    rule_name, rx, need_valid = ent[0], ent[1], bool(ent[2])
                elif len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                    need_valid = True
                else:
                    continue
            else:
                # 네임드 객체(SimpleNamespace 등)
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
                need_valid = bool(getattr(ent, "need_valid", True))
            if rx is None:
                continue
        except Exception:
            continue

        validator = _get_validator(rule_name)

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and validator:
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False  # 검증 예외는 실패로 간주

            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(kind="xlsx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "xlsx", text


# 파일 단위 레닥션: 시트/공유문자열/차트/차트.rels 처리
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 1) 셀/공유문자열: 텍스트 노드 마스킹
    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        b, _ = sub_text_nodes(data, comp)
        return b

    # 2) 차트 본문: a:t, c:strCache 라벨 마스킹 (+ 남은 텍스트 노드 안전망)
    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return b2

    # 3) 차트 관계(.rels)
    if low.startswith("xl/charts/_rels/") and low.endswith(".rels"):
        b3, _ = chart_rels_sanitize(data)
        return b3

    # 4) 기타 파트는 원본 유지
    return data
