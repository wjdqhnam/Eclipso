from __future__ import annotations

import io
import re
import zipfile
import logging
import os
import inspect
from typing import List, Tuple

try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
        chart_rels_sanitize,
        sanitize_docx_content_types,
    )
except Exception:  # pragma: no cover - 구조가 달라졌을 때 대비
    from server.modules.common import (  # type: ignore
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
        chart_rels_sanitize,
        sanitize_docx_content_types,
    )

# ── schemas 임포트: core 우선, 실패 시 대안 경로 시도 ─────────────────────────
try:
    from ..core.schemas import XmlMatch, XmlLocation
except Exception:  # pragma: no cover
    from server.core.schemas import XmlMatch, XmlLocation  # type: ignore

log = logging.getLogger("docx_module")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] docx_module: %(message)s"))
    log.addHandler(_h)
log.setLevel(logging.INFO)

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp")

try:
    from .ocr_image_redactor import redact_image_bytes
except Exception:
    try:
        from server.modules.ocr_image_redactor import redact_image_bytes
    except Exception:
        redact_image_bytes = None


# 환경변수 bool 파싱 유틸
def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")



def _call_redact_image_bytes(fn, data: bytes, comp, *, filename: str, env_prefix: str, logger, debug: bool):

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

def _collect_chart_texts(zipf: zipfile.ZipFile) -> str:
    parts: List[str] = []

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("word/charts/") and n.endswith(".xml")
    ):
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s,
            re.I | re.DOTALL,
        ):
            text_part = m.group(1)
            num_part = m.group(2)
            v = (text_part or num_part or "").strip()
            if not v:
                continue
            # 숫자값(축 값 등)만 있는 건 제외
            if num_part is not None and re.fullmatch(r"\d+(\.\d+)?", v):
                continue
            parts.append(v)

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("word/embeddings/") and n.lower().endswith(".xlsx")
    ):
        try:
            xlsx_bytes = zipf.read(name)
        except KeyError:
            continue

        try:
            with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as xzf:
                parts.append(xlsx_text_from_zip(xzf))
        except zipfile.BadZipFile:
            continue

    return cleanup_text("\n".join(p for p in parts if p))
def docx_text(zipf: zipfile.ZipFile) -> str:
    try:
        xml_bytes = zipf.read("word/document.xml")
    except KeyError:
        xml_bytes = b""

    xml = xml_bytes.decode("utf-8", "ignore")
    text_main = "".join(
        m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL)
    )
    text_main = cleanup_text(text_main)

    # 차트 + 임베디드 XLSX
    text_charts = _collect_chart_texts(zipf)

    return cleanup_text("\n".join(x for x in [text_main, text_charts] if x))

def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = docx_text(zipf)
    return {
        "full_text": txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = docx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                if len(ent) < 2:
                    continue
                rule_name, rx = ent[0], ent[1]
            else:
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
            if rx is None:
                continue
        except Exception:
            continue

        for m in rx.finditer(text):
            val = m.group(0)
            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=True,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(kind="docx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "docx", text

def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()
    log.info(
        "[DOCX][RED] filename=%s low=%s size=%d",
        filename,
        low,
        len(data) if isinstance(data, (bytes, bytearray)) else -1,
    )

    if low == "[content_types].xml":
        return sanitize_docx_content_types(data)

    # 차트 관계(rels) 중 외부 링크 제거
    if low.startswith("word/charts/_rels/") and low.endswith(".rels"):
        return chart_rels_sanitize(data)

    if low == "word/document.xml":
        return sub_text_nodes(data, comp)[0]

    if low.startswith("word/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    if low.startswith("word/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    if low.startswith("word/media/") and low.endswith(IMAGE_EXTS):
        log.info("[DOCX][IMG] image=%s size=%d", filename, len(data))

        if not _env_bool("DOCX_OCR_IMAGES", True):
            log.info("[DOCX][IMG][OCR] 비활성화됨(DOCX_OCR_IMAGES=0) image=%s", filename)
            return data

        if redact_image_bytes is None:
            log.warning("[DOCX][IMG][OCR] ocr_image_redactor 없음 -> 스킵(%s)", filename)
            return data

        debug = _env_bool("DOCX_OCR_DEBUG", False)

        log.info(
            "[DOCX][IMG][OCR] start image=%s size=%d debug=%s",
            filename,
            len(data),
            debug,
        )

        try:
            red, hit = _call_redact_image_bytes(
                redact_image_bytes,
                data,
                comp,
                filename=filename,
                env_prefix="DOCX",
                logger=log,
                debug=debug,
            )

            changed = (red != data)
            log.info(
                "[DOCX][IMG][OCR] end image=%s in=%d out=%d changed=%s hit=%s",
                filename,
                len(data),
                len(red) if isinstance(red, (bytes, bytearray)) else -1,
                changed,
                hit,
            )

            if hit == -1:
                if changed:
                    log.info("[DOCX][IMG][OCR] 변경됨=%s (hit 카운트 없음, 바이트만 변경)", filename)
                else:
                    log.info("[DOCX][IMG][OCR] 변경없음=%s (hit 카운트 없음, 바이트 동일)", filename)
            else:
                if hit > 0:
                    log.info("[DOCX][IMG][OCR] 마스킹됨=%s hits=%d", filename, hit)
                else:
                    log.info("[DOCX][IMG][OCR] 매칭없음=%s hits=%d", filename, hit)

            return red

        except Exception as e:
            log.exception("[DOCX][IMG][OCR] 실패 image=%s err=%r", filename, e)
            return data

    return data


def extract_images(file_bytes: bytes) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        names = zipf.namelist()
        log.info("[DOCX][IMG-EXTRACT] entries=%d", len(names))

        for name in names:
            low = name.lower()
            if not low.startswith("word/media/"):
                continue
            if not low.endswith(IMAGE_EXTS):
                continue
            try:
                data = zipf.read(name)
            except KeyError:
                continue
            out.append((name, data))
            log.info("[DOCX][IMG-EXTRACT] name=%s size=%d", name, len(data))

    log.info("[DOCX][IMG-EXTRACT] total=%d", len(out))
    return out
