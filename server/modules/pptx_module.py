from __future__ import annotations

import io
import os
import re
import zipfile
import logging
import inspect
from typing import List, Tuple, Optional

# 공통 유틸 (상대 import 우선, 실패 시 절대 import)
try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )
except Exception:
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )

from server.core.schemas import XmlMatch, XmlLocation

log = logging.getLogger("xml_redaction")

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp")

# 이미지 OCR 레닥션 엔진(있으면 사용, 없으면 skip)
try:
    from .ocr_image_redactor import redact_image_bytes
except Exception:
    try:
        from server.modules.ocr_image_redactor import redact_image_bytes
    except Exception:
        redact_image_bytes = None


# ─────────────────────────────────────────────────────────────
# XML 태그/노이즈 제거 (text/extract 미리보기용 공통 정리)
# ─────────────────────────────────────────────────────────────
_XML_TAG_RX = re.compile(r"(?s)<[^>]+>")

def _clean_extracted_text(txt: str) -> str:
    """
    PPTX의 chart/xml 등에서 raw 태그 덩어리가 섞여 들어오는 문제 방지용.
    - 태그 제거
    - '<' '>' 남아있는 라인 통째 삭제
    - 차트/임베디드에서 튀는 엑셀 참조/formatCode 노이즈 제거
    """
    if not txt:
        return ""

    t = (txt or "").replace("\r", "")

    # 1) 태그 완전 제거(여러 줄 포함)
    t = _XML_TAG_RX.sub(" ", t)

    # 2) 그래도 남는 '<' '>' 포함 라인은 통째로 제거
    lines: List[str] = []
    for line in t.splitlines():
        s = (line or "").strip()
        if not s:
            continue
        if "<" in s or ">" in s:
            continue
        lines.append(s)
    t = "\n".join(lines)

    # 3) 엑셀 참조/포맷 노이즈 제거 (차트 numRef 등에서 자주 튐)
    t = re.sub(r"Sheet\d*!\$[A-Z]+\$\d+(?::\$[A-Z]+\$\d+)?", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\bGeneral\b(?=\s*\d)", "", t, flags=re.IGNORECASE)

    return cleanup_text(t)


def _env_bool(key: str, default: bool) -> bool:
    # env flag 읽기
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _ensure_ocr_env_compat(env_prefix: str):
    # 기존 키(HWPX_OCR_MIN_CONF 등)와 신규 키(PPTX_OCR_MINCONF 등) 혼용 대응
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
    # redact_image_bytes 시그니처 차이(버전별) 흡수 + (bytes, hit) / bytes 반환 모두 처리
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

    # 4) (data, comp=<...>/rules=<...>, **kwargs)
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


def _redact_image_bytes(image_bytes: bytes, comp, *, filename: str) -> Tuple[bytes, int]:
    # PPTX 이미지 → OCR 레닥션(가능한 경우만)
    if redact_image_bytes is None:
        log.warning("[PPTX][IMG][OCR] ocr_image_redactor not available -> skip (%s)", filename)
        return image_bytes, 0

    if not _env_bool("PPTX_OCR_IMAGES", True):
        log.info("[PPTX][IMG][OCR] disabled by env (PPTX_OCR_IMAGES=0) image=%s", filename)
        return image_bytes, 0

    _ensure_ocr_env_compat("PPTX")

    debug = _env_bool("PPTX_OCR_DEBUG", False)

    try:
        red, hit = _call_redact_image_bytes(
            redact_image_bytes,
            image_bytes,
            comp,
            filename=filename,
            env_prefix="PPTX",
            logger=log,
            debug=debug,
        )
        changed = (red != image_bytes)
        log.info(
            "[PPTX][IMG][OCR] end image=%s in=%d out=%d changed=%s hit=%s",
            filename,
            len(image_bytes),
            len(red),
            changed,
            hit,
        )
        return red, hit
    except Exception as e:
        log.exception("[PPTX][IMG][OCR] failed image=%s err=%r", filename, e)
        return image_bytes, 0


def _collect_chart_and_embedded_texts(zipf: zipfile.ZipFile) -> str:
    # 차트 XML + 임베디드 XLSX 텍스트 수집
    parts: List[str] = []

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/charts/") and n.endswith(".xml")
    ):
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        # 차트는 <a:t>, <c:v>에 들어있는 값만 추출하되, 혹시 태그가 섞이면 마지막에 정리
        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s,
            re.IGNORECASE | re.DOTALL,
        ):
            v = (m.group(1) or m.group(2) or "").strip()
            if v:
                parts.append(v)

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/embeddings/") and n.lower().endswith(".xlsx")
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

    # ✅ 여기서 한 번 정리(태그/노이즈 제거) → 미리보기로 raw 태그가 새지 않게
    return _clean_extracted_text("\n".join(p for p in parts if p))


def pptx_text(zipf: zipfile.ZipFile) -> str:
    # 슬라이드 텍스트 + 차트/임베디드 텍스트 합치기
    all_txt: List[str] = []

    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/slides/") and n.endswith(".xml")
    ):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        all_txt += [
            (m.group(1) or "").strip()
            for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)
            if (m.group(1) or "").strip()
        ]

    chart_txt = _collect_chart_and_embedded_texts(zipf)
    if chart_txt:
        all_txt.append(chart_txt)

    # ✅ 최종 합친 뒤에도 한 번 더 정리
    return _clean_extracted_text("\n".join(all_txt))


def extract_text(file_bytes: bytes) -> dict:
    # /text/extract용
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = pptx_text(zipf)
    return {"full_text": txt, "pages": [{"page": 1, "text": txt}]}


def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    # 룰 기반 스캔(텍스트만)
    text = pptx_text(zipf)
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
                    location=XmlLocation(kind="pptx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "pptx", text


def redact_item(filename: str, data: bytes, comp):
    # PPTX entry 단위 레닥션(슬라이드/차트/임베디드/이미지 OCR)
    low = filename.lower()
    log.info(
        "[PPTX][RED] filename=%s low=%s size=%d",
        filename,
        low,
        len(data) if isinstance(data, (bytes, bytearray)) else -1,
    )

    if low.startswith("ppt/slides/") and low.endswith(".xml"):
        b, _ = sub_text_nodes(data, comp)
        return b

    if low.startswith("ppt/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        b3, _ = sub_text_nodes(b2, comp)
        return b3

    if low.startswith("ppt/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    if low.startswith("ppt/media/") and low.endswith(IMAGE_EXTS):
        log.info("[PPTX][IMG] image=%s size=%d", filename, len(data))

        red, hit = _redact_image_bytes(data, comp, filename=filename)
        if hit > 0 and red != data:
            log.info("[PPTX][IMG][OCR] redacted=%s hits=%d", filename, hit)
            return red

        return data

    return data


def extract_images(file_bytes: bytes) -> List[Tuple[str, bytes]]:
    # 디버그용 이미지 추출
    out: List[Tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        names = zipf.namelist()
        log.info("[PPTX][IMG-EXTRACT] entries=%d", len(names))
        for name in names:
            low = name.lower()
            if not low.startswith("ppt/media/"):
                continue
            if not low.endswith(IMAGE_EXTS):
                continue
            try:
                data = zipf.read(name)
            except KeyError:
                continue
            out.append((name, data))
            log.info("[PPTX][IMG-EXTRACT] name=%s size=%d", name, len(data))
    log.info("[PPTX][IMG-EXTRACT] total=%d", len(out))
    return out
