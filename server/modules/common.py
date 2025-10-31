# server/xml/common.py
from __future__ import annotations
import io, re, zipfile, xml.etree.ElementTree as ET
from typing import Tuple, List, Dict
from ..core.redaction_rules import PRESET_PATTERNS, RULES

# ---------- 옵션(HWPX에서 사용) ----------
HWPX_STRIP_PREVIEW = True
HWPX_DISABLE_CACHE = True
HWPX_BLANK_PREVIEW = False
HWPX_BLANK_OLE_BINDATA = False

# ---------- 텍스트 정리 ----------
_FOOTNOTE_PATTERNS = [
    re.compile(r"\s*\(\^\d+\)"),
    re.compile(r"\s*\^\d+\)"),
    re.compile(r"\s*\^\d+\."),
    re.compile(r"\s*\^\d+\b"),
]
def cleanup_text(text: str) -> str:
    if not text: return ""
    t = text
    for rx in _FOOTNOTE_PATTERNS: t = rx.sub("", t)
    t = re.sub(r"[\x00-\x09\x0B-\x1F]", " ", t)
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    return t.strip()

# ---------- 룰 컴파일 + 우선순위 ----------
_RULE_PRIORITY = {
    "card": 100, "email": 90, "rrn": 80, "fgn": 80,
    "phone_mobile": 60, "phone_city": 60, "phone_service": 60,
    "driver_license": 40, "passport": 30,
}
def compile_rules():
    comp = []
    for r in PRESET_PATTERNS:
        name = r["name"]; pat = r["regex"]
        flags = 0 if r.get("case_sensitive") else re.IGNORECASE
        if r.get("whole_word"): pat = rf"\b(?:{pat})\b"
        prio = _RULE_PRIORITY.get(name, 0)
        comp.append((name, re.compile(pat, flags), bool(r.get("ensure_valid", False)), prio))
    comp.sort(key=lambda t: t[3], reverse=True)
    return comp

def is_valid(kind: str, value: str) -> bool:
    rule = RULES.get((kind or "").lower())
    if rule:
        validator = rule.get("validator")
        if callable(validator):
            try: return bool(validator(value))
            except TypeError: return bool(validator(value, None))
    return True

# ---------- 마스킹 유틸 ----------
def _mask_keep_seps(s: str) -> str:
    return "".join("*" if ch.isalnum() else ch for ch in s)
def _mask_email(v: str) -> str:
    return "".join(ch if ch == "@" else "*" for ch in v)
def mask_for(rule: str, v: str) -> str:
    return _mask_email(v) if (rule or "").lower()=="email" else _mask_keep_seps(v)

def mask_text_with_priority(txt: str, comp) -> tuple[str, int]:
    if not txt: return "", 0
    taken: List[tuple[int,int]] = []; repls: List[tuple[int,int,str]] = []
    def ov(a0,a1,b0,b1): return not (a1<=b0 or b1<=a0)
    for name, rx, need_valid, _prio in comp:
        for m in rx.finditer(txt):
            s,e = m.span()
            if any(ov(s,e,ts,te) for ts,te in taken): continue
            val = m.group(0)
            if need_valid and not is_valid(name, val): continue
            taken.append((s,e)); repls.append((s,e, mask_for(name, val)))
    if not repls: return txt, 0
    repls.sort(key=lambda r:r[0], reverse=True)
    out = list(txt)
    for s,e,rep in repls: out[s:e] = list(rep)
    return "".join(out), len(repls)

# ---------- XML 텍스트 노드 치환 ----------
_TEXT_NODE_RE = re.compile(r">(?!\s*<)([^<]+)<", re.DOTALL)
def sub_text_nodes(xml_bytes: bytes, comp) -> Tuple[bytes,int]:
    s = xml_bytes.decode("utf-8", "ignore")
    def _apply(txt: str) -> str:
        masked, _ = mask_text_with_priority(txt, comp); return masked
    out = _TEXT_NODE_RE.sub(lambda m: ">" + _apply(m.group(1)) + "<", s)
    return out.encode("utf-8","ignore"), 0

# ---------- 인코딩/ET ----------
def _detect_xml_encoding(b: bytes) -> str:
    m = re.match(rb'^<\?xml[^>]*encoding=["\']([^"\']+)["\']', b.strip()[:200], re.I)
    if m:
        enc = m.group(1).decode("ascii","ignore")
        enc_low = enc.lower().replace("-","").replace("_","")
        return "utf-8" if enc_low in ("utf8","utf") else enc
    return "utf-8"
def et_from_bytes(xml_bytes: bytes) -> tuple[ET.ElementTree,str]:
    enc = _detect_xml_encoding(xml_bytes)
    try: s = xml_bytes.decode(enc, "strict")
    except Exception: s = xml_bytes.decode(enc, "ignore")
    return ET.ElementTree(ET.fromstring(s)), enc
def et_to_bytes(tree: ET.ElementTree, enc: str) -> bytes:
    bio = io.BytesIO(); tree.write(bio, encoding=enc, xml_declaration=True); return bio.getvalue()

# ---------- 차트 무해화(레이아웃 유지) ----------
_NS = {
    "c": "http://schemas.openxmlformats.org/drawingml/2006/chart",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
}
_C_EXTERNAL_RE = re.compile(rb"(?is)<\s*c:externalData\b[^>]*>.*?</\s*c:externalData\s*>")
def _strip_chart_external_data(xml_bytes: bytes) -> tuple[bytes,int]:
    after = _C_EXTERNAL_RE.sub(b"", xml_bytes); return (after,1) if after!=xml_bytes else (xml_bytes,0)

def chart_sanitize(xml_bytes: bytes, comp) -> tuple[bytes,int]:
    b2, ext = _strip_chart_external_data(xml_bytes)
    tree, enc = et_from_bytes(b2); root = tree.getroot(); hits = ext
    for f in root.findall(".//c:f", _NS):
        if f.text: f.text = ""; hits += 1
    # strCache
    for v in root.findall(".//c:strCache//c:pt/c:v", _NS):
        if v.text is not None:
            new, cnt = mask_text_with_priority(v.text, comp)
            if cnt: v.text = new; hits += cnt
    # numCache
    for v in root.findall(".//c:numCache//c:pt/c:v", _NS):
        if v.text is not None:
            new, cnt = mask_text_with_priority(v.text, comp)
            if cnt: v.text = new; hits += cnt
    # labels
    for t in root.findall(".//a:t", _NS):
        if t.text:
            new, cnt = mask_text_with_priority(t.text, comp)
            if cnt: t.text = new; hits += cnt
    return et_to_bytes(tree, enc), hits

# ---------- XLSX 텍스트 수집(공유) ----------
def xlsx_text_from_zip(zipf: zipfile.ZipFile) -> str:
    out = []
    for name in zipf.namelist():
        if name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/"):
            try:
                xml = zipf.read(name).decode("utf-8","ignore")
                out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
            except KeyError: pass
    for name in (n for n in zipf.namelist() if n.startswith("xl/charts/") and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8","ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I|re.DOTALL):
            v = (m.group(1) or m.group(2) or "").strip()
            if v: out.append(v)
    return cleanup_text("\n".join(out))

# ---------- 내장 XLSX 레닥션(공유) ----------
def redact_embedded_xlsx_bytes(xlsx_bytes: bytes) -> bytes:
    comp = compile_rules()
    bio_in = io.BytesIO(xlsx_bytes); bio_out = io.BytesIO()
    with zipfile.ZipFile(bio_in,"r") as zin, zipfile.ZipFile(bio_out,"w",zipfile.ZIP_DEFLATED) as zout:
        for it in zin.infolist():
            name = it.filename; data = zin.read(name); low = name.lower()
            if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
                data, _ = sub_text_nodes(data, comp)
            elif low.startswith("xl/charts/") and low.endswith(".xml"):
                data, _ = chart_sanitize(data, comp)
            zout.writestr(it, data)
    return bio_out.getvalue()

# ---------- OLE 보수 마스킹(공유) ----------
_PHONE_ASCII_RX = re.compile(rb'(?<!\d)\d{2,4}\s*-\s*\d{3,4}\s*-\s*\d{4}(?!\d)')
_EMAIL_ASCII_RX = re.compile(rb'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
_CARD_ASCII_RX  = re.compile(rb'(?<!\d)\d{4}(?:\s*-\s*|\s)\d{4}(?:\s*-\s*|\s)\d{4}(?:\s*-\s*|\s)\d{4}(?!\d)')
_PHONE_U16_RX   = re.compile(rb'(?:(?<!\x00\d)\d\x00){2,4}\s?\x00-\x00\s?\x00(?:(?:\d\x00){3,4})\s?\x00-\x00\s?\x00(?:(?:\d\x00){4})(?!\x00\d)')
_EMAIL_U16_RX   = re.compile(rb'(?:[A-Za-z0-9._%+\-]\x00)+@\x00(?:[A-Za-z0-9.\-]\x00)+\.\x00(?:[A-Za-z]{2,}\x00)')
_CARD_U16_RX    = re.compile(
    rb'(?:(?:\d\x00){4})(?:\s?\x00-\x00\s?\x00|\s\x00)'
    rb'(?:(?:\d\x00){4})(?:\s?\x00-\x00\s?\x00|\s\x00)'
    rb'(?:(?:\d\x00){4})(?:\s?\x00-\x00\s?\x00|\s\x00)'
    rb'(?:(?:\d\x00){4})(?!\x00)'
)
def _mask_ascii_span(buf: bytearray, s: int, e: int, keep_at=False):
    for i in range(s,e):
        b = buf[i]
        if 48<=b<=57 or 65<=b<=90 or 97<=b<=122: buf[i] = 0x2A
        elif keep_at and b==64: pass
def _mask_utf16le_span(buf: bytearray, s: int, e: int, keep_at=False):
    for i in range(s,e,2):
        lo, hi = buf[i], buf[i+1]
        if hi==0x00:
            if (0x30<=lo<=0x39) or (0x41<=lo<=0x5A) or (0x61<=lo<=0x7A): buf[i],buf[i+1]=0x2A,0x00
            elif keep_at and lo==0x40: pass
def _mask_regex_ascii(buf: bytearray, rx: re.Pattern, keep_at=False) -> int:
    hits=0; bnow=bytes(buf)
    for m in list(rx.finditer(bnow)): _mask_ascii_span(buf,m.start(),m.end(),keep_at); hits+=1
    return hits
def _mask_regex_u16(buf: bytearray, rx: re.Pattern, keep_at=False) -> int:
    hits=0; bnow=bytes(buf)
    for m in list(rx.finditer(bnow)): _mask_utf16le_span(buf,m.start(),m.end(),keep_at); hits+=1
    return hits

def redact_ole_conservative(data: bytes) -> bytes:
    b = bytearray(data)
    # ASCII 덩어리
    ascii_chunks = []; start=None
    for i, by in enumerate(b):
        if 32<=by<=126:
            if start is None: start=i
        else:
            if start is not None and (i-start)>=6: ascii_chunks.append((start,i))
            start=None
    if start is not None and (len(b)-start)>=6: ascii_chunks.append((start,len(b)))
    comp = compile_rules()
    def _red_str(txt: str) -> str:
        new, _ = mask_text_with_priority(txt, comp); return new
    for s,e in ascii_chunks:
        try: txt = bytes(b[s:e]).decode('ascii','ignore')
        except Exception: continue
        nb = _red_str(txt).encode('ascii','ignore')
        if len(nb) < (e-s): nb = nb + b'*'*((e-s)-len(nb))
        elif len(nb) > (e-s): nb = nb[:(e-s)]
        b[s:e] = nb
    # UTF-16LE 덩어리
    i=0; n=len(b)
    while i+4<=n:
        j=i; good=0
        while j+1<n and (32<=b[j]<=126) and b[j+1]==0x00: good+=1; j+=2
        if good>=4:
            s,e=i,j
            try: txt = bytes(b[s:e]).decode('utf-16le','ignore')
            except Exception: i=j; continue
            nb = _red_str(txt).encode('utf-16le','ignore')
            if len(nb) < (e-s): nb = nb + b'\x2A\x00'*(((e-s)-len(nb))//2)
            elif len(nb) > (e-s): nb = nb[:(e-s)]
            b[s:e] = nb; i=j
        else: i+=2
    _mask_regex_ascii(b, _PHONE_ASCII_RX)
    _mask_regex_u16(b, _PHONE_U16_RX)
    _mask_regex_ascii(b, _EMAIL_ASCII_RX, keep_at=True)
    _mask_regex_u16(b, _EMAIL_U16_RX, keep_at=True)
    _mask_regex_ascii(b, _CARD_ASCII_RX)
    _mask_regex_u16(b, _CARD_U16_RX)
    return bytes(b)
