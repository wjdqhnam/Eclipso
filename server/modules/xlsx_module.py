# server/xml/xlsx.py
from __future__ import annotations
import zipfile
from typing import List, Tuple
from .common import cleanup_text, compile_rules, sub_text_nodes, chart_sanitize, xlsx_text_from_zip
from ..core.schemas import XmlMatch, XmlLocation

def xlsx_text(zipf: zipfile.ZipFile) -> str:
    return xlsx_text_from_zip(zipf)

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            out.append(XmlMatch(
                rule=rule_name, value=m.group(0), valid=True,
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="xlsx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "xlsx", text

def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()
    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        return sub_text_nodes(data, comp)[0]
    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]
    return data

def extract_text(file_bytes: bytes) -> dict:
    """XLSX 파일에서 셀 텍스트 추출"""
    import io, zipfile, re
    from server.modules.common import cleanup_text

    try:
        with io.BytesIO(file_bytes) as bio, zipfile.ZipFile(bio, "r") as zipf:
            all_txt = []
            for name in sorted(n for n in zipf.namelist() if n.endswith(".xml")):
                xml = zipf.read(name).decode("utf-8", "ignore")
                matches = re.findall(r">([^<>]+)<", xml)
                all_txt.extend(matches)
            joined = "\n".join(all_txt)
            return {"full_text": cleanup_text(joined)}
    except Exception as e:
        raise Exception(f"XLSX 텍스트 추출 실패: {e}")