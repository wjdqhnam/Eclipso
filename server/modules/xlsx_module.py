from __future__ import annotations

import io
import zipfile
import re
import unicodedata
import os
import inspect
import logging
from typing import List, Tuple, Optional

try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
    )
except Exception:
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
    )

from server.core.schemas import XmlMatch, XmlLocation

log = logging.getLogger("xml_redaction")

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp")

# OCR 이미지 레닥션 엔진(있으면 사용, 없으면 skip)
try:
    from .ocr_image_redactor import redact_image_bytes  # type: ignore
except Exception:
    try:
        from server.modules.ocr_image_redactor import redact_image_bytes  # type: ignore
    except Exception:
        redact_image_bytes = None  # type: ignore


def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _call_redact_image_bytes(fn, data: bytes, comp, *, filename: str, env_prefix: str, logger, debug: bool):
    # redact_image_bytes 시그니처/반환 형태가 달라도 최대한 호환 호출
    kwargs = {}
    try:
        sig = inspect.signature(fn)
        params = sig.parameters
        has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

        def _set_kw(k: str, v):
            if v is None:
                return
            if has_varkw or (k in params):
                kwargs[k] = v

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
        has_varkw = False
        comp_kw_name = None
        pos_count = 0

    last_err = None

    def _normalize_ret(ret):
        # (bytes, hit)
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

        # bytes only
        if isinstance(ret, bytearray):
            return bytes(ret), -1
        if isinstance(ret, bytes):
            return ret, -1

        return None

    # 1) (data, comp, **kwargs)
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

    # 2) (data, **kwargs)
    try:
        ret = fn(data, **kwargs)
        nr = _normalize_ret(ret)
        if nr is not None:
            return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    # 3) (data)
    try:
        ret = fn(data)
        nr = _normalize_ret(ret)
        if nr is not None:
            return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    # 4) (data, rules/comp=<...>, **kwargs)
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


# ────────────────────────────────────────────────────
# XLSX 텍스트 추출
# ────────────────────────────────────────────────────
def xlsx_text(zipf: zipfile.ZipFile) -> str:
    out: List[str] = []

    # 1) sharedStrings
    try:
        sst = zipf.read("xl/sharedStrings.xml").decode("utf-8", "ignore")
        for m in re.finditer(r"<t[^>]*>(.*?)</t>", sst, re.DOTALL):
            v = (m.group(1) or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            out.append(v)
    except KeyError:
        pass

    # 2) worksheets: <v>, <t>
    for name in (
        n for n in zipf.namelist()
        if n.startswith("xl/worksheets/") and n.endswith(".xml")
    ):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        for m in re.finditer(r"<v[^>]*>(.*?)</v>", xml, re.DOTALL):
            v = (m.group(1) or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            if re.fullmatch(r"\d{1,4}", v):
                continue
            out.append(v)

        for m in re.finditer(r"<t[^>]*>(.*?)</t>", xml, re.DOTALL):
            v = (m.group(1) or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            out.append(v)

    # 3) charts: <a:t>, <c:v>
    for name in (
        n for n in zipf.namelist()
        if n.startswith("xl/charts/") and n.endswith(".xml")
    ):
        try:
            s2 = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s2,
            re.IGNORECASE | re.DOTALL,
        ):
            text_part = m.group(1)
            num_part = m.group(2)
            v = (text_part or num_part or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            if num_part is not None and re.fullmatch(r"\d{1,4}", v):
                continue
            out.append(v)

    text = cleanup_text("\n".join(out))

    filtered_lines: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if "<c:" in s:
            continue
        if s.endswith(":") and not re.search(r"[0-9@]", s):
            continue
        filtered_lines.append(line)

    return "\n".join(filtered_lines)


def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = xlsx_text(zipf)
    return {"full_text": txt, "pages": [{"page": 1, "text": txt}]}


def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 5:
                    rule_name, rx, need_valid, _prio, validator = ent[0], ent[1], bool(ent[2]), ent[3], ent[4]
                elif len(ent) >= 3:
                    rule_name, rx, need_valid = ent[0], ent[1], bool(ent[2])
                    validator = None
                elif len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                    need_valid, validator = True, None
                else:
                    continue
            else:
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
                need_valid = bool(getattr(ent, "need_valid", True))
                validator = getattr(ent, "validator", None)
            if rx is None:
                continue
        except Exception:
            continue

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and callable(validator):
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
                    location=XmlLocation(kind="xlsx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "xlsx", text


def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()
    log.info("[XLSX][RED] filename=%s low=%s size=%d", filename, low, len(data))

    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        b, _ = sub_text_nodes(data, comp)
        return b

    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return b2

    if low.startswith("xl/media/") and low.endswith(IMAGE_EXTS):
        log.info("[XLSX][IMG] image=%s size=%d", filename, len(data))

        if not _env_bool("XLSX_OCR_IMAGES", True):
            log.info("[XLSX][IMG][OCR] disabled by env (XLSX_OCR_IMAGES=0) image=%s", filename)
            return data

        if redact_image_bytes is None:
            log.warning("[XLSX][IMG][OCR] ocr_image_redactor not available -> skip (%s)", filename)
            return data

        debug = _env_bool("XLSX_OCR_DEBUG", False)

        log.info("[XLSX][IMG][OCR] start image=%s size=%d debug=%s", filename, len(data), debug)
        try:
            red, hit = _call_redact_image_bytes(
                redact_image_bytes,
                data,
                comp,
                filename=filename,
                env_prefix="XLSX",
                logger=log,
                debug=debug,
            )

            changed = (red != data)
            log.info(
                "[XLSX][IMG][OCR] end image=%s in=%d out=%d changed=%s hit=%s",
                filename,
                len(data),
                len(red) if isinstance(red, (bytes, bytearray)) else -1,
                changed,
                hit,
            )

            if hit == -1:
                return red
            if hit > 0:
                return red
            return data

        except Exception as e:
            log.exception("[XLSX][IMG][OCR] failed image=%s err=%r", filename, e)
            return data

    return data


def extract_images(file_bytes: bytes) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as z:
        for name in z.namelist():
            low = name.lower()
            if low.startswith("xl/media/") and low.endswith(IMAGE_EXTS):
                try:
                    data = z.read(name)
                    out.append((name, data))
                    log.info("[XLSX][IMG] image=%s size=%d", name, len(data))
                except KeyError:
                    pass
    return out
