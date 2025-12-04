from __future__ import annotations
import io, re, zipfile, logging
from typing import List, Tuple, Optional

try:
    from .common import (
        cleanup_text, compile_rules, sub_text_nodes, chart_sanitize,
        redact_embedded_xlsx_bytes, HWPX_DISABLE_CACHE
    )
except Exception:
    from server.modules.common import (
        cleanup_text, compile_rules, sub_text_nodes, chart_sanitize,
        redact_embedded_xlsx_bytes, HWPX_DISABLE_CACHE
    )

try:
    from ..core.schemas import XmlMatch, XmlLocation
except Exception:
    from server.core.schemas import XmlMatch, XmlLocation  

log = logging.getLogger("xml_redaction")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] xml_redaction: %(message)s"))
    log.addHandler(_h)
log.setLevel(logging.INFO)

_CURRENT_SECRETS: List[str] = []
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp")


def set_hwpx_secrets(values: List[str] | None):
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))

# HWPX 내부 텍스트 수집

def hwpx_text(zipf: zipfile.ZipFile) -> str:
    out: List[str] = []
    names = zipf.namelist()

    # 본문 (Contents/)
    for name in sorted(n for n in names if n.lower().startswith("contents/") and n.endswith(".xml")):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
            out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
        except Exception:
            pass

    # 차트 (chart/, charts/)
    for name in sorted(n for n in names if (n.lower().startswith("chart/") or n.lower().startswith("charts/")) and n.endswith(".xml")):
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
            for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I | re.DOTALL):
                v = (m.group(1) or m.group(2) or "").strip()
                if v:
                    out.append(v)
        except Exception:
            pass

    # BinData/
    for name in names:
        low = name.lower()
        if not low.startswith("bindata/"):
            continue
        try:
            b = zipf.read(name)
        except KeyError:
            continue

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


# ───────────────────────────────────────
# /text/extract 에서 사용되는 텍스트 포맷 정리
# ───────────────────────────────────────
def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        raw = hwpx_text(zipf)

    txt = re.sub(r"<[^>\n]+>", "", raw)

    lines = []
    for line in txt.splitlines():
        if re.fullmatch(r"\(?\^\d+[\).\s]*", line.strip()):
            continue
        lines.append(line)
    txt = "\n".join(lines)
    txt = re.sub(r"\(\^\d+\)", "", txt)
    txt = re.sub(
        r"Sheet\d*!\$[A-Z]+\$\d+(?::\$[A-Z]+\$\d+)?",
        "",
        txt, flags=re.IGNORECASE
    )
    txt = re.sub(r"General(?=\s*\d)", "", txt, flags=re.IGNORECASE)
    cleaned = cleanup_text(txt)
    return {"full_text": cleaned, "pages": [{"page": 1, "text": cleaned}]}


# ───────────────────────────────────────
# 스캔(민감정보 추출)
# ───────────────────────────────────────
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = hwpx_text(zipf)
    comp = compile_rules()

    try:
        from ..core.redaction_rules import RULES
    except Exception:
        from server.core.redaction_rules import RULES

    def _validator(rule):
        try:
            v = RULES.get(rule, {}).get("validator")
            return v if callable(v) else None
        except Exception:
            return None

    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                rule, rx = ent[0], ent[1]
                need_valid = bool(ent[2]) if len(ent) >= 3 else True
            else:
                rule = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", None)
                need_valid = bool(getattr(ent, "need_valid", True))
            if rx is None:
                continue
        except Exception:
            continue

        vfunc = _validator(rule)

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and vfunc:
                try:
                    ok = bool(vfunc(val))
                except Exception:
                    ok = False

            out.append(
                XmlMatch(
                    rule=rule, value=val, valid=ok,
                    context=text[max(0, m.start()-20): m.end()+20],
                    location=XmlLocation(kind="hwpx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "hwpx", text


# ───────────────────────────────────────
# 레닥션 (파트별 처리)
# ───────────────────────────────────────
def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    low = filename.lower()
    log.info("[HWPX][RED] entry=%s size=%d", filename, len(data))

    if low.startswith("preview/"):
        if low.endswith(IMAGE_EXTS):
            log.info("[HWPX][IMG] preview image=%s size=%d", filename, len(data))
        return b""
    
    if HWPX_DISABLE_CACHE and low.endswith("settings.xml"):
        try:
            txt = data.decode("utf-8", "ignore")
            txt = re.sub(r'(?i)usepreview\s*=\s*"(?:true|1)"', 'usePreview="false"', txt)
            txt = re.sub(r"(?is)<preview>.*?</preview>", "<preview>0</preview>", txt)
            txt = re.sub(r"(?is)<cache>.*?</cache>", "<cache>0</cache>", txt)
            return txt.encode("utf-8", "ignore")
        except Exception:
            return data

    if low.startswith("contents/") and low.endswith(".xml"):
        return sub_text_nodes(data, comp)[0]

    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    if low.startswith("images/") or low.startswith("image/"):
        if low.endswith(IMAGE_EXTS):
            log.info("[HWPX][IMG] image=%s size=%d", filename, len(data))
        return data

    if low.startswith("bindata/"):
        log.info("[HWPX][BIN] bindata entry=%s size=%d", filename, len(data))
        if low.endswith(IMAGE_EXTS):
            log.info("[HWPX][IMG] bindata image=%s size=%d", filename, len(data))

        if data[:2] == b"PK":
            try:
                return redact_embedded_xlsx_bytes(data)
            except Exception:
                return data
        try:
            try:
                from .ole_redactor import redact_ole_bin_preserve_size
            except Exception:
                from server.modules.ole_redactor import redact_ole_bin_preserve_size  
            return redact_ole_bin_preserve_size(data, _CURRENT_SECRETS, mask_preview=True)
        except Exception:
            return data

    if low.endswith(".xml") and not low.startswith("preview/"):
        return sub_text_nodes(data, comp)[0]

    return None


def extract_images(file_bytes: bytes) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as z:
        for name in z.namelist():
            low = name.lower()
            if not (
                low.startswith("preview/") or
                low.startswith("images/") or
                low.startswith("image/") or
                low.startswith("bindata/")
            ):
                continue
            if low.endswith(IMAGE_EXTS):
                try:
                    out.append((name, z.read(name)))
                except KeyError:
                    pass
    return out
