from __future__ import annotations

import io
import re
import zipfile
import logging
from typing import Optional, List, Tuple

try:
    import numpy as np
    from PIL import Image, ImageDraw
except Exception:
    np = None
    Image = None
    ImageDraw = None
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
    from server.modules.common import (  # type: ignore
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        redact_embedded_xlsx_bytes,
        HWPX_STRIP_PREVIEW,
        HWPX_DISABLE_CACHE,
        HWPX_BLANK_PREVIEW,
    )

try:
    from .ocr_module import run_paddle_ocr, OcrItem
except Exception:  # pragma: no cover
    from server.modules.ocr_module import run_paddle_ocr, OcrItem  # type: ignore

from server.core.schemas import XmlMatch, XmlLocation
from server.core.normalize import normalization_text

log = logging.getLogger("xml_redaction")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    log.addHandler(_h)
    log.propagate = False
log.setLevel(logging.INFO)

_CURRENT_SECRETS: List[str] = []


def set_hwpx_secrets(values: List[str] | None):
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))


# ── 값 단위 정규화 (공통 normalization + OCR 노이즈 보정) ─────────────────────
def _normalize_for_match(text: str) -> str:
    t = normalization_text(text)
    t = re.sub(r"\bb(?=\d)", "0", t)
    return t


# ── HWPX 내부 이미지에서 OCR 텍스트 추출 ──────────────────────────────────────
def _hwpx_ocr_text(zipf: zipfile.ZipFile) -> str:
    if Image is None or np is None:
        return ""

    texts: List[str] = []

    for name in zipf.namelist():
        low = name.lower()

        if not (
            low.endswith(".png")
            or low.endswith(".jpg")
            or low.endswith(".jpeg")
            or low.endswith(".bmp")
        ):
            continue

        if not (
            low.startswith("preview/")
            or low.startswith("images/")
            or low.startswith("image/")
        ):
            continue

        try:
            b = zipf.read(name)
        except KeyError:
            continue

        try:
            with Image.open(io.BytesIO(b)) as img:
                img = img.convert("RGB")
                arr = np.asarray(img)

            ocr_items = run_paddle_ocr(arr)
            log.info("[HWPX][OCR] file=%s items=%d", name, len(ocr_items))
            for it in ocr_items:
                if it.text:
                    log.info(
                        "[HWPX][OCR RAW] file=%s text='%s' score=%.6f",
                        name,
                        it.text,
                        it.score,
                    )
                    texts.append(it.text)
        except Exception:
            continue

    return "\n".join(t for t in texts if t)


# ── 텍스트 수집 (본문/차트 + OCR) ────────────────────────────────────────
def hwpx_text(zipf: zipfile.ZipFile) -> str:
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
        if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(
            ".xml"
        ):
            try:
                s = zipf.read(name).decode("utf-8", "ignore")
                for m in re.finditer(
                    r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
                    s,
                    re.I | re.DOTALL,
                ):
                    v = (m.group(1) or m.group(2) or "").strip()
                    if v:
                        out.append(v)
            except Exception:
                pass

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
                    except Exception:  # pragma: no cover
                        from server.modules.common import xlsx_text_from_zip  # type: ignore
                    with zipfile.ZipFile(io.BytesIO(b), "r") as ez:
                        out.append(xlsx_text_from_zip(ez))
                except Exception:
                    pass

    # 이미지 OCR
    try:
        ocr_txt = _hwpx_ocr_text(zipf)
        if ocr_txt:
            out.append(ocr_txt)
            log.info(
                "[HWPX][OCR] images=%d ocr_items=%d merged_len=%d",
                1,
                len(ocr_txt.splitlines()),
                len(ocr_txt),
            )
    except Exception:
        pass

    merged = "\n".join(x for x in out if x)
    log.info("[HWPX] hwpx_text merged_len=%d", len(merged))
    return merged


def extract_text(file_bytes: bytes) -> dict:
    log.info("[HWPX] extract_text: size=%d", len(file_bytes))
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
    txt = re.sub(
        r"Sheet\d*!\$[A-Z]+\$\d+(?::\$[A-Z]+\$\d+)?", "", txt, flags=re.IGNORECASE
    )
    txt = re.sub(r"General(?=\s*\d)", "", txt, flags=re.IGNORECASE)

    normalized = _normalize_for_match(txt)
    log.info("[HWPX] extract_text: cleaned_len=%d", len(normalized))

    return {"full_text": normalized, "pages": [{"page": 1, "text": normalized}]}


def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    log.info("[HWPX] scan() start")
    raw_text = hwpx_text(zipf)
    text = _normalize_for_match(raw_text)
    log.info("[HWPX] scan text_len=%d", len(text))

    comp = compile_rules()

    # ← 여기 import fallback 정리 (..redaction_rules 제거)
    try:
        from ..core.redaction_rules import RULES
    except Exception:  # pragma: no cover
        from server.core.redaction_rules import RULES  # type: ignore

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
                    location=XmlLocation(
                        kind="hwpx",
                        part="*merged_text*",
                        start=m.start(),
                        end=m.end(),
                    ),
                )
            )

    ok_summary: dict[str, int] = {}
    fail_summary: dict[str, int] = {}
    for m in out:
        if m.valid:
            ok_summary[m.rule] = ok_summary.get(m.rule, 0) + 1
        else:
            fail_summary[m.rule] = fail_summary.get(m.rule, 0) + 1
    log.info("[HWPX] scan summary OK=%s FAIL=%s", ok_summary or {}, fail_summary or {})

    return out, "hwpx", text


def _log_sub_result(kind: str, filename: str, stat) -> None:
    try:
        if isinstance(stat, int):
            cnt = stat
        else:
            cnt = len(stat or [])
    except Exception:
        cnt = -1
    log.info("[HWPX][XML] kind=%s file=%s replaced=%d", kind, filename, cnt)


# ── 이미지 파일(OCR 기반 부분 레닥션) 유틸 ─────────────────────────────────────
def _redact_image_with_ocr_bytes(
    filename: str, data: bytes, comp
) -> Tuple[Optional[bytes], int]:
    if Image is None or ImageDraw is None or np is None:
        return None, 0

    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return None, 0

    try:
        img = img.convert("RGB")
        arr = np.asarray(img)
    except Exception:
        return None, 0

    try:
        ocr_items: List[OcrItem] = run_paddle_ocr(arr)
    except Exception:
        return None, 0

    if not ocr_items:
        return None, 0

    # ← 여기 import fallback 도 정리
    try:
        from ..core.redaction_rules import RULES
    except Exception:  # pragma: no cover
        from server.core.redaction_rules import RULES  # type: ignore

    def _get_validator(rule_name: str):
        try:
            v = RULES.get(rule_name, {}).get("validator")
        except Exception:
            v = None
        return v if callable(v) else None

    draw = ImageDraw.Draw(img)
    masked_count = 0

    for it in ocr_items:
        raw_txt = it.text or ""
        text_norm = _normalize_for_match(raw_txt)

        matched_this_box = False

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
            m = rx.search(text_norm)
            if not m:
                continue

            val = m.group(0)
            ok = True
            validator = _get_validator(rule_name)
            if need_valid and validator:
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False

            if not ok:
                continue
            try:
                x1, y1, x2, y2 = it.bbox
                draw.rectangle([x1, y1, x2, y2], fill="black")
                masked_count += 1
                matched_this_box = True
            except Exception:
                pass
            if matched_this_box:
                break

    if masked_count <= 0:
        return None, 0

    low = filename.lower()
    if low.endswith(".jpg") or low.endswith(".jpeg"):
        fmt = "JPEG"
    elif low.endswith(".bmp"):
        fmt = "BMP"
    else:
        fmt = "PNG"

    buf = io.BytesIO()
    try:
        img.save(buf, format=fmt)
    except Exception:
        return None, 0

    out = buf.getvalue()
    log.info(
        "[HWPX][IMG-OCR] file=%s → OCR 기반 bbox %d개 레닥션 (out_size=%d)",
        filename,
        masked_count,
        len(out),
    )
    return out, masked_count


def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    low = filename.lower()
    log.info(
        "[HWPX][RED] filename=%s low=%s size=%d",
        filename,
        low,
        len(data) if isinstance(data, (bytes, bytearray)) else -1,
    )

    # 프리뷰는 통째로 제거 또는 OCR 기반 레닥션
    if low.startswith("preview/"):
        if (
            low.endswith(".png")
            or low.endswith(".jpg")
            or low.endswith(".jpeg")
            or low.endswith(".bmp")
        ):
            # OCR 기반 부분 레닥션 시도
            try:
                red, cnt = _redact_image_with_ocr_bytes(filename, data, comp)
                if red is not None and cnt > 0:
                    return red
            except Exception:
                log.info("[HWPX][IMG] file=%s OCR 기반 레닥션 실패 → 전체 블랙으로 대체", filename)
            try:
                if Image is not None:
                    with Image.open(io.BytesIO(data)) as img:
                        w, h = img.size
                else:
                    w, h = 1024, 768
                if Image is not None:
                    black = Image.new("RGB", (w, h), (0, 0, 0))
                    buf = io.BytesIO()
                    if low.endswith(".jpg") or low.endswith(".jpeg"):
                        fmt = "JPEG"
                    elif low.endswith(".bmp"):
                        fmt = "BMP"
                    else:
                        fmt = "PNG"
                    black.save(buf, format=fmt)
                    out = buf.getvalue()
                else:
                    out = data
                log.info(
                    "[HWPX][IMG] file=%s → 블랙 이미지로 레닥션 (size=%d)",
                    filename,
                    len(out),
                )
                return out
            except Exception:
                log.info("[HWPX][IMG] file=%s 블랙 처리 실패 → 제거", filename)
                return b""
        return b""

    # settings: 캐시/프리뷰 끄기
    if HWPX_DISABLE_CACHE and low.endswith("settings.xml"):
        try:
            txt = data.decode("utf-8", "ignore")
            txt = re.sub(
                r'(?i)usepreview\s*=\s*"(?:true|1)"', 'usePreview="false"', txt
            )
            txt = re.sub(
                r"(?i)usepreview\s*=\s*'(?:true|1)'", "usePreview='false'", txt
            )
            txt = re.sub(
                r"(?is)<\s*usepreview\s*>.*?</\s*usepreview\s*>",
                "<usePreview>false</usePreview>",
                txt,
            )
            txt = re.sub(
                r"(?is)<\s*preview\s*>.*?</\s*preview\s*>", "<preview>0</preview>", txt
            )
            txt = re.sub(
                r'(?i)usecache\s*=\s*"(?:true|1)"', 'useCache="false"', txt
            )
            txt = re.sub(
                r"(?is)<\s*cache\s*>.*?</\s*cache\s*>", "<cache>0</cache>", txt
            )
            return txt.encode("utf-8", "ignore")
        except Exception:
            return data

    # BinData: 이미지 / OLE
    if low.startswith("bindata/"):
        if (
            low.endswith(".png")
            or low.endswith(".jpg")
            or low.endswith(".jpeg")
            or low.endswith(".bmp")
        ):
            try:
                red, cnt = _redact_image_with_ocr_bytes(filename, data, comp)
                if red is not None and cnt > 0:
                    return red
            except Exception:
                log.info(
                    "[HWPX][IMG] BinData image file=%s OCR 기반 레닥션 실패 → fallback",
                    filename,
                )

        if len(data) >= 4 and data[:2] == b"PK":
            try:
                return redact_embedded_xlsx_bytes(data)
            except Exception:
                return data

        try:
            try:
                from .ole_redactor import redact_ole_bin_preserve_size
            except Exception:  # pragma: no cover
                from server.modules.ole_redactor import (  # type: ignore
                    redact_ole_bin_preserve_size,
                )
            return redact_ole_bin_preserve_size(
                data, _CURRENT_SECRETS, mask_preview=True
            )
        except Exception:
            return data

    # 본문
    if low.startswith("contents/") and low.endswith(".xml"):
        masked, stat = sub_text_nodes(data, comp)
        _log_sub_result("contents", filename, stat)
        return masked

    # 차트
    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(
        ".xml"
    ):
        b2, _ = chart_sanitize(data, comp)
        masked, stat = sub_text_nodes(b2, comp)
        _log_sub_result("chart", filename, stat)
        return masked

    if low.endswith(".xml") and not low.startswith("preview/"):
        masked, stat = sub_text_nodes(data, comp)
        _log_sub_result("other-xml", filename, stat)
        return masked

    return None
