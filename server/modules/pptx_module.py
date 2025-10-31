# server/xml/pptx.py
from __future__ import annotations
import re, zipfile
from typing import List, Tuple
from .common import cleanup_text, compile_rules, sub_text_nodes, chart_sanitize
from ..core.schemas import XmlMatch, XmlLocation

def pptx_text(zipf: zipfile.ZipFile) -> str:
    all_txt = []
    for name in sorted(n for n in zipf.namelist() if n.startswith("ppt/slides/") and n.endswith(".xml")):
        xml = zipf.read(name).decode("utf-8","ignore")
        all_txt += [tm.group(1) for tm in re.finditer(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)]
    # charts
    for name in sorted(n for n in zipf.namelist() if n.startswith("ppt/charts/") and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8","ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I|re.DOTALL):
            v = (m.group(1) or m.group(2) or "")
            if v: all_txt.append(v)
    return cleanup_text("\n".join(all_txt))

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = pptx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            out.append(XmlMatch(
                rule=rule_name, value=m.group(0), valid=True,
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="pptx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "pptx", text

def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()
    if low.startswith("ppt/slides/") and low.endswith(".xml"):
        return sub_text_nodes(data, comp)[0]
    if low.startswith("ppt/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]
    return data

def extract_text(file_bytes: bytes) -> dict:
    """PPTX 파일에서 텍스트 추출"""
    import io, zipfile, re
    from server.modules.common import cleanup_text

    try:
        with io.BytesIO(file_bytes) as bio, zipfile.ZipFile(bio, "r") as zipf:
            all_txt = []
            # 슬라이드 내 텍스트
            for name in sorted(n for n in zipf.namelist() if n.startswith("ppt/slides/") and n.endswith(".xml")):
                xml = zipf.read(name).decode("utf-8", "ignore")
                all_txt += re.findall(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)
            # 차트 데이터 텍스트
            for name in sorted(n for n in zipf.namelist() if n.startswith("ppt/charts/") and n.endswith(".xml")):
                xml = zipf.read(name).decode("utf-8", "ignore")
                all_txt += re.findall(r"<c:v[^>]*>(.*?)</c:v>", xml, re.DOTALL)
            joined = "\n".join(all_txt)
            return {"full_text": cleanup_text(joined)}
    except Exception as e:
        raise Exception(f"PPTX 텍스트 추출 실패: {e}")