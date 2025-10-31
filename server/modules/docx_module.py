# server/xml/docx.py
from __future__ import annotations
import re, zipfile
from typing import List, Tuple
from ..modules.common import cleanup_text, compile_rules, sub_text_nodes, chart_sanitize
from ..core.schemas import XmlMatch, XmlLocation

def docx_text(zipf: zipfile.ZipFile) -> str:
    try:
        xml = zipf.read("word/document.xml").decode("utf-8","ignore")
    except KeyError:
        xml = ""
    text_main = "".join(m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL))
    text_main = cleanup_text(text_main)
    # charts
    parts = []
    for name in sorted(n for n in zipf.namelist() if n.startswith("word/charts/") and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8","ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I|re.DOTALL):
            v = (m.group(1) or m.group(2) or "")
            if v: parts.append(v)
    text_charts = cleanup_text("\n".join(parts)) if parts else ""
    return cleanup_text("\n".join(x for x in [text_main, text_charts] if x))

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = docx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            val = m.group(0)
            ok = True  # 스캔은 valid 라벨만 붙임(필요시 validators 연결 가능)
            out.append(XmlMatch(
                rule=rule_name, value=val, valid=ok,
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="docx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "docx", text

def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()
    if low == "word/document.xml":
        return sub_text_nodes(data, comp)[0]
    if low.startswith("word/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]
    return data

def extract_text(file_bytes: bytes) -> dict:
    """DOCX 파일에서 텍스트 추출"""
    import io, zipfile, re
    from server.modules.common import cleanup_text

    try:
        with io.BytesIO(file_bytes) as bio, zipfile.ZipFile(bio, "r") as zipf:
            all_txt = []
            # Word 문단 및 표 텍스트
            for name in sorted(n for n in zipf.namelist() if n.startswith("word/") and n.endswith(".xml")):
                xml = zipf.read(name).decode("utf-8", "ignore")
                for m in re.finditer(r">([^<>]+)<", xml):
                    all_txt.append(m.group(1))
            joined = "\n".join(all_txt)
            return {"full_text": cleanup_text(joined)}
    except Exception as e:
        raise Exception(f"DOCX 텍스트 추출 실패: {e}")
