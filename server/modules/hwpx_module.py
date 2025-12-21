from __future__ import annotations

import io
import os
import re
import zipfile
import logging
import inspect
from typing import List, Tuple, Optional

try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        redact_embedded_xlsx_bytes,
        HWPX_DISABLE_CACHE,
    )
except Exception:
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        redact_embedded_xlsx_bytes,
        HWPX_DISABLE_CACHE,
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

try:
    from .ocr_image_redactor import redact_image_bytes  # type: ignore
except Exception:
    try:
        from server.modules.ocr_image_redactor import redact_image_bytes  # type: ignore
    except Exception:
        redact_image_bytes = None  # type: ignore


def set_hwpx_secrets(values: List[str] | None):
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))


def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _env_float(key: str, default: float) -> float:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


def _ensure_ocr_env_compat(env_prefix: str):
    # 기존 HWPX_OCR_MIN_CONF(언더스코어) -> ocr_image_redactor에서 쓰는 HWPX_OCR_MINCONF(붙여쓰기)로 브릿지
    mapping = [
        ("OCR_MINCONF", "OCR_MIN_CONF"),
        ("OCR_MINCONF2", "OCR_MIN_CONF2"),
        ("OCR_MINCONF3", "OCR_MIN_CONF3"),
    ]

    for new_tail, old_tail in mapping:
        new_k = f"{env_prefix}_{new_tail}"
        old_k = f"{env_prefix}_{old_tail}"
        if os.getenv(new_k) is None and os.getenv(old_k) is not None:
            os.environ[new_k] = os.getenv(old_k) or ""


def _call_redact_image_bytes(fn, data: bytes, comp, *, filename: str, env_prefix: str, logger, debug: bool):
    # 프로젝트별 시그니처 차이 방어 (bytes 또는 (bytes, hit) 반환 모두 수용)
    kwargs = {}
    try:
        sig = inspect.signature(fn)
        params = sig.parameters
        has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

        def _set_kw(key: str, value):
            if value is None:
                return
            if has_varkw or (key in params):
                kwargs[key] = value

        _set_kw("filename", filename)
        _set_kw("name", filename)
        _set_kw("path", filename)

        _set_kw("env_prefix", env_prefix)
        _set_kw("prefix", env_prefix)
        _set_kw("env", env_prefix)

        _set_kw("logger", logger)
        _set_kw("log", logger)

        if debug:
            _set_kw("debug", True)
            _set_kw("verbose", True)
            _set_kw("trace", True)

        comp_kw_name = None
        for cand in ("comp", "compiled", "compiled_rules", "rules"):
            if has_varkw or (cand in params):
                comp_kw_name = cand
                break

        pos_params = [
            p for p in params.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        pos_count = len(pos_params)

    except Exception:
        sig = None
        params = {}
        has_varkw = False
        comp_kw_name = None
        pos_count = 0

    last_err = None

    def _normalize_ret(ret):
        if isinstance(ret, tuple) and len(ret) == 2:
            red, hit = ret
            if isinstance(red, bytearray):
                red = bytes(red)
            if isinstance(red, bytes):
                try:
                    return red, int(hit)
                except Exception:
                    return red, -1
            return None
        if isinstance(ret, bytearray):
            return bytes(ret), -1
        if isinstance(ret, bytes):
            return ret, -1
        return None

    try:
        if sig is None or has_varkw or pos_count >= 2:
            ret = fn(data, comp, **kwargs)
            nr = _normalize_ret(ret)
            if nr is not None:
                return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    try:
        ret = fn(data, **kwargs)
        nr = _normalize_ret(ret)
        if nr is not None:
            return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    try:
        ret = fn(data)
        nr = _normalize_ret(ret)
        if nr is not None:
            return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    try:
        if comp_kw_name is not None:
            kw2 = dict(kwargs)
            kw2[comp_kw_name] = comp
            ret = fn(data, **kw2)
            nr = _normalize_ret(ret)
            if nr is not None:
                return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    raise TypeError(f"redact_image_bytes call failed: {last_err!r}")


def _redact_image_bytes(image_bytes: bytes, comp, *, filename: str = "?") -> Tuple[bytes, int]:
    if redact_image_bytes is None:
        return image_bytes, 0

    ocr_on = _env_bool("HWPX_OCR_IMAGES", True)
    if not ocr_on:
        return image_bytes, 0

    _ensure_ocr_env_compat("HWPX")

    debug = _env_bool("HWPX_OCR_DEBUG", False)
    fill = os.getenv("HWPX_OCR_FILL", "black") or "black"

    try:
        red, hit = _call_redact_image_bytes(
            redact_image_bytes,
            image_bytes,
            comp,
            filename=filename,
            env_prefix="HWPX",
            logger=log,
            debug=debug,
        )
    except Exception as e:
        log.exception("[HWPX][IMG][OCR] failed image=%s err=%r", filename, e)
        return image_bytes, 0

    if red != image_bytes:
        if hit <= 0:
            log.info("[HWPX][IMG][OCR] changed(no hit count?) image=%s", filename)
        else:
            log.info("[HWPX][IMG][OCR] redacted=%s hits=%d", filename, hit)
    else:
        if debug:
            log.info("[HWPX][IMG][OCR] no-change image=%s hit=%s", filename, hit)

    # fill은 함수 내부에서 파라미터로 받을 수도 있고(env로도 읽음). env로 쓰는 쪽이 일관적이라 유지.
    _ = fill
    return red, hit


def hwpx_text(zipf: zipfile.ZipFile) -> str:
    out: List[str] = []
    names = zipf.namelist()

    for name in sorted(n for n in names if n.lower().startswith("contents/") and n.endswith(".xml")):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
            out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
        except Exception:
            pass

    for name in sorted(
        n for n in names
        if (n.lower().startswith("chart/") or n.lower().startswith("charts/")) and n.endswith(".xml")
    ):
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
            for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I | re.DOTALL):
                v = (m.group(1) or m.group(2) or "").strip()
                if v:
                    out.append(v)
        except Exception:
            pass

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
    txt = re.sub(r"Sheet\d*!\$[A-Z]+\$\d+(?::\$[A-Z]+\$\d+)?", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"General(?=\s*\d)", "", txt, flags=re.IGNORECASE)

    cleaned = cleanup_text(txt)
    return {"full_text": cleaned, "pages": [{"page": 1, "text": cleaned}]}


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
                    rule=rule,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): m.end() + 20],
                    location=XmlLocation(kind="hwpx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "hwpx", text


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
            red, hit = _redact_image_bytes(data, comp, filename=filename)
            if hit > 0:
                log.info("[HWPX][IMG][OCR] redacted=%s hits=%d", filename, hit)
                return red
        return data

    if low.startswith("bindata/"):
        log.info("[HWPX][BIN] bindata entry=%s size=%d", filename, len(data))

        if low.endswith(IMAGE_EXTS):
            log.info("[HWPX][IMG] bindata image=%s size=%d", filename, len(data))
            red, hit = _redact_image_bytes(data, comp, filename=filename)
            if hit > 0:
                log.info("[HWPX][IMG][OCR] redacted=%s hits=%d", filename, hit)
                return red
            return data

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
                low.startswith("preview/")
                or low.startswith("images/")
                or low.startswith("image/")
                or low.startswith("bindata/")
            ):
                continue
            if low.endswith(IMAGE_EXTS):
                try:
                    out.append((name, z.read(name)))
                except KeyError:
                    pass
    return out
