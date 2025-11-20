from __future__ import annotations
import io
import re
import zipfile
import unicodedata
from typing import List, Tuple, Optional, Callable

from server.core.redaction_rules import PRESET_PATTERNS, RULES

__all__ = [
    "cleanup_text",
    "compile_rules",
    "sub_text_nodes",
    "chart_sanitize",
    "xlsx_text_from_zip",
    "redact_embedded_xlsx_bytes",
    "HWPX_STRIP_PREVIEW",
    "HWPX_DISABLE_CACHE",
    "HWPX_BLANK_PREVIEW",
]

# 옵션
HWPX_STRIP_PREVIEW = False
HWPX_DISABLE_CACHE = True
HWPX_BLANK_PREVIEW = True

# 텍스트 정리(개행/공백 + 유니코드 NFKC)
def cleanup_text(text: str) -> str:
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        t = unicodedata.normalize("NFKC", t)
    except Exception:
        pass
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    return t.strip()

# 정규식 룰 컴파일(+우선순위/validator)
_RULE_PRIORITY = {
    "card": 100, "email": 90, "rrn": 80, "fgn": 80,
    "phone_mobile": 60, "phone_city": 60,
    "driver_license": 40, "passport": 30,
}

def compile_rules() -> List[Tuple[str, re.Pattern, bool, int, Optional[Callable]]]:
    comp: List[Tuple[str, re.Pattern, bool, int, Optional[Callable]]] = []
    for r in PRESET_PATTERNS:
        name = r["name"]
        pat = r["regex"]
        flags = 0 if r.get("case_sensitive") else re.IGNORECASE
        if r.get("whole_word"):
            pat = rf"\b(?:{pat})\b"
        prio = _RULE_PRIORITY.get(name, 0)
        rule_key = (name or "").lower()
        validator = RULES.get(rule_key, {}).get("validator")
        validator = validator if callable(validator) else None
        ensure_valid_flag = r.get("ensure_valid", None)
        need_valid = (validator is not None) if ensure_valid_flag is None else bool(ensure_valid_flag)
        comp.append((name, re.compile(pat, flags), need_valid, prio, validator))
    comp.sort(key=lambda t: t[3], reverse=True)
    return comp

# validator 호출 래퍼
def _is_valid(value: str, validator: Optional[Callable]) -> bool:
    if not validator:
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            return bool(validator(value, None))
    except Exception:
        return False

# 마스킹 유틸(HTML 엔티티 보존)
_ENTITY_RE = re.compile(r"&(#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);")

def _mask_preserving_entities(v: str, mask_char_fn) -> str:
    out: List[str] = []
    i = 0
    n = len(v)
    while i < n:
        if v[i] == "&":
            m = _ENTITY_RE.match(v, i)
            if m:
                out.append(v[i:m.end()])
                i = m.end()
                continue
        out.append(mask_char_fn(v[i]))
        i += 1
    return "".join(out)

def _mask_email(v: str) -> str:
    def _m(ch: str) -> str:
        if ch in ("@", "-"):
            return ch
        if ch.isalnum() or ch in "._":
            return "*"
        return ch
    return _mask_preserving_entities(v, _m)

def _mask_keep_rules(v: str) -> str:
    def _m(ch: str) -> str:
        if ch == "-":
            return ch
        if ch.isalnum() or ch in "._":
            return "*"
        return ch
    return _mask_preserving_entities(v, _m)

def _mask_value(rule: str, v: str) -> str:
    return _mask_email(v) if (rule or "").lower() == "email" else _mask_keep_rules(v)

# 매칭 스팬 수집/필터/적용
def _collect_spans(src: str, comp) -> tuple[List[tuple], List[tuple]]:
    allowed: List[tuple] = []
    forbidden: List[tuple] = []
    for name, rx, need_valid, prio, validator in comp:
        for m in rx.finditer(src):
            s, e = m.span()
            val = m.group(0)
            if need_valid and not _is_valid(val, validator):
                forbidden.append((s, e))
            else:
                allowed.append((s, e, name, prio))
    return allowed, forbidden

def _overlap(a0, a1, b0, b1) -> bool:
    return not (a1 <= b0 or b1 <= a0)

def _filter_allowed_by_forbidden(allowed, forbidden):
    if not forbidden:
        return allowed
    out = []
    for s, e, nm, pr in allowed:
        if any(_overlap(s, e, fs, fe) for fs, fe in forbidden):
            continue
        out.append((s, e, nm, pr))
    return out

def _apply_spans(src: str, allowed) -> tuple[str, int]:
    if not allowed:
        return src, 0
    allowed.sort(key=lambda t: (t[0], -t[3], -(t[1] - t[0])))
    out = list(src)
    hits = 0
    for s, e, nm, _pr in sorted(allowed, key=lambda t: t[0], reverse=True):
        out[s:e] = list(_mask_value(nm, src[s:e]))
        hits += 1
    return "".join(out), hits

# XML 텍스트 노드 마스킹
_TEXT_NODE_RE = re.compile(r">([^<>]+)<", re.DOTALL)

def sub_text_nodes(xml_bytes: bytes, comp) -> Tuple[bytes, int]:
    s = xml_bytes.decode("utf-8", "ignore")
    all_allowed: List[tuple] = []
    all_forbidden: List[tuple] = []
    for m in _TEXT_NODE_RE.finditer(s):
        txt = m.group(1)
        if not txt:
            continue
        base = m.start(1)
        allowed, forbidden = _collect_spans(txt, comp)
        for a_s, a_e, nm, pr in allowed:
            all_allowed.append((base + a_s, base + a_e, nm, pr))
        for f_s, f_e in forbidden:
            all_forbidden.append((base + f_s, base + f_e))
    all_allowed = _filter_allowed_by_forbidden(all_allowed, all_forbidden)
    masked, hits = _apply_spans(s, all_allowed)
    return masked.encode("utf-8", "ignore"), hits

# 차트 라벨/값 마스킹(XML)
def chart_sanitize(xml_bytes: bytes, comp) -> Tuple[bytes, int]:
    return sub_text_nodes(xml_bytes, comp)

# DOCX ContentTypes 패스스루(훅용 자리)
def sanitize_docx_content_types(xml_bytes: bytes) -> bytes:
    return xml_bytes

# XLSX 텍스트 수집(sharedStrings/worksheets/charts) 확인용
def xlsx_text_from_zip(zipf: zipfile.ZipFile) -> str:
    out: List[str] = []
    try:
        sst = zipf.read("xl/sharedStrings.xml").decode("utf-8", "ignore")
        out += [m.group(1) for m in re.finditer(r"<t[^>]*>(.*?)</t>", sst, re.DOTALL)]
    except KeyError:
        pass
    for name in (n for n in zipf.namelist() if n.startswith("xl/worksheets/") and n.endswith(".xml")):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
            out += [m.group(1) for m in re.finditer(r"<v[^>]*>(.*?)</v>", xml, re.DOTALL)]
            out += [m.group(1) for m in re.finditer(r"<t[^>]*>(.*?)</t>", xml, re.DOTALL)]
        except KeyError:
            continue
    for name in (n for n in zipf.namelist() if n.startswith("xl/charts/") and n.endswith(".xml")):
        try:
            s2 = zipf.read(name).decode("utf-8", "ignore")
            for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s2, re.I | re.DOTALL):
                v = (m.group(1) or m.group(2) or "").strip()
                if v:
                    out.append(v)
        except KeyError:
            continue
    return cleanup_text("\n".join(out))

# 내장 XLSX 레닥션(ZIP 리라이트)
def redact_embedded_xlsx_bytes(xlsx_bytes: bytes) -> bytes:
    comp = compile_rules()
    bio_in = io.BytesIO(xlsx_bytes)
    bio_out = io.BytesIO()
    with zipfile.ZipFile(bio_in, "r") as zin, zipfile.ZipFile(bio_out, "w", zipfile.ZIP_DEFLATED) as zout:
        for it in zin.infolist():
            name = it.filename
            data = zin.read(name)
            low = name.lower()
            if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
                data, _ = sub_text_nodes(data, comp)
            elif low.startswith("xl/charts/") and low.endswith(".xml"):
                data, _ = chart_sanitize(data, comp)
            zout.writestr(it, data)
    return bio_out.getvalue()
