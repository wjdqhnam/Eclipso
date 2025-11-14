from __future__ import annotations

import io
import re
import zipfile
import logging
from typing import Optional, List, Tuple

try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        redact_embedded_xlsx_bytes,
        HWPX_STRIP_PREVIEW,
        HWPX_DISABLE_CACHE,
        HWPX_BLANK_PREVIEW,
    )
except Exception:
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        redact_embedded_xlsx_bytes,
        HWPX_STRIP_PREVIEW,
        HWPX_DISABLE_CACHE,
        HWPX_BLANK_PREVIEW,
    )

# schemas
from server.core.schemas import XmlMatch, XmlLocation

log = logging.getLogger("xml_redaction")

# OLE 프리뷰 마스킹용 캐시
_CURRENT_SECRETS: List[str] = []


def set_hwpx_secrets(values: List[str] | None):
    # 중복 제거 + None 필터
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))


def hwpx_text(zipf: zipfile.ZipFile) -> str:
    # 본문/차트/내장 XLSX 텍스트 긁어서 cleanup_text로 정리
    out: List[str] = []
    names = zipf.namelist()

    # 본문
    for name in sorted(names):
        low = name.lower()
        if low.startswith("contents/") and low.endswith(".xml"):
            try:
                xml = zipf.read(name).decode("utf-8", "ignore")
                out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
            except Exception:
                pass

    # 차트
    for name in sorted(names):
        low = name.lower()
        if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
            try:
                s = zipf.read(name).decode("utf-8", "ignore")
                for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I | re.DOTALL):
                    v = (m.group(1) or m.group(2) or "").strip()
                    if v:
                        out.append(v)
            except Exception:
                pass

    # BinData 내장 XLSX
    for name in names:
        low = name.lower()
        if low.startswith("bindata/"):
            try:
                b = zipf.read(name)
            except KeyError:
                b = b""
            if len(b) >= 4 and b[:2] == b"PK":
                try:
                    try:
                        from .common import xlsx_text_from_zip
                    except Exception:
                        from server.modules.common import xlsx_text_from_zip
                    with zipfile.ZipFile(io.BytesIO(b), "r") as ez:
                        out.append(xlsx_text_from_zip(ez))
                except Exception:
                    pass

    return cleanup_text("\n".join(x for x in out if x))


def extract_text(file_bytes: bytes) -> dict:
    #보기 좋게 후처리
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        raw = hwpx_text(zipf)

    txt = re.sub(r"<[^>\n]+>", "", raw)
    lines: List[str] = []
    for line in txt.splitlines():
        s = line.strip()
        if re.fullmatch(r"\(?\^\d+[\).\s]*", s):
            continue
        lines.append(line)
    txt = "\n".join(lines)
    txt = re.sub(r"\(\^\d+\)", "", txt)
    # 엑셀 참조 토큰/General 포맷 제거
    txt = re.sub(r"Sheet\d*!\$[A-Z]+\$\d+(?::\$[A-Z]+\$\d+)?", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"General(?=\s*\d)", "", txt, flags=re.IGNORECASE)

    cleaned = cleanup_text(txt)
    return {"full_text": cleaned, "pages": [{"page": 1, "text": cleaned}]}


def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    # 정규식 룰 매칭 (validator 있으면 검사)
    text = hwpx_text(zipf)
    comp = compile_rules()

    # 🔧 여기 임포트 블록만 수정됨 (언더스코어/공백 오류 수정)
    try:
        from ..core.redaction_rules import RULES
    except Exception:
        try:
            from ..redaction_rules import RULES
        except Exception:
            from server.core.redaction_rules import RULES

    def _get_validator(rule_name: str):
        try:
            v = RULES.get(rule_name, {}).get("validator")
        except Exception:
            v = None
        return v if callable(v) else None

    out: List[XmlMatch] = []
    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                rule_name = ent[0]
                rx = ent[1]
                need_valid = bool(ent[2]) if len(ent) >= 3 else True
            else:
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
                    ok = False

            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(kind="hwpx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "hwpx", text


def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    # 파트별 레닥션 엔트리
    low = filename.lower()

    # 프리뷰는 통째로 제거
    if low.startswith("preview/"):
        return b""

    # settings: 캐시/프리뷰 끄기
    if HWPX_DISABLE_CACHE and low.endswith("settings.xml"):
        try:
            txt = data.decode("utf-8", "ignore")
            txt = re.sub(r'(?i)usepreview\s*=\s*"(?:true|1)"', 'usePreview="false"', txt)
            txt = re.sub(r"(?i)usepreview\s*=\s*'(?:true|1)'", "usePreview='false'", txt)
            txt = re.sub(r"(?is)<\s*usepreview\s*>.*?</\s*usepreview\s*>", "<usePreview>false</usePreview>", txt)
            txt = re.sub(r"(?is)<\s*preview\s*>.*?</\s*preview\s*>", "<preview>0</preview>", txt)
            txt = re.sub(r'(?i)usecache\s*=\s*"(?:true|1)"', 'useCache="false"', txt)
            txt = re.sub(r"(?is)<\s*cache\s*>.*?</\s*cache\s*>", "<cache>0</cache>", txt)
            return txt.encode("utf-8", "ignore")
        except Exception:
            return data

    # 본문
    if low.startswith("contents/") and low.endswith(".xml"):
        masked, _ = sub_text_nodes(data, comp)
        return masked

    # 차트
    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        masked, _ = sub_text_nodes(b2, comp)
        return masked

    # BinData: XLSX/OLE
    if low.startswith("bindata/"):
        # 내장 XLSX
        if len(data) >= 4 and data[:2] == b"PK":
            try:
                return redact_embedded_xlsx_bytes(data)
            except Exception:
                return data
        # OLE 프리뷰는 사이즈 유지 마스킹
        try:
            try:
                from .ole_redactor import redact_ole_bin_preserve_size
            except Exception:
                from server.modules.ole_redactor import redact_ole_bin_preserve_size  # type: ignore
            return redact_ole_bin_preserve_size(data, _CURRENT_SECRETS, mask_preview=True)
        except Exception:
            return data

    # 나머지 XML 파트는 텍스트 노드만 처리
    if low.endswith(".xml") and not low.startswith("preview/"):
        masked, _ = sub_text_nodes(data, comp)
        return masked

    return None
