from __future__ import annotations

import io
import zipfile
import re
import unicodedata
import os
import inspect
import logging
import xml.etree.ElementTree as ET
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


# XLSX 텍스트 추출
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


def _xlsx_col_to_index(col: str) -> int:
    # A -> 0, B -> 1, Z -> 25, AA -> 26 ...
    n = 0
    for ch in col.upper():
        if not ("A" <= ch <= "Z"):
            continue
        n = n * 26 + (ord(ch) - ord("A") + 1)
    return max(0, n - 1)


def _xlsx_cell_ref_to_rc(ref: str) -> Tuple[int, int]:
    # "C5" -> (row_idx=4, col_idx=2)
    s = (ref or "").strip()
    if not s:
        return (0, 0)
    col = []
    row = []
    for ch in s:
        if ch.isalpha():
            col.append(ch)
        elif ch.isdigit():
            row.append(ch)
    r = int("".join(row)) - 1 if row else 0
    c = _xlsx_col_to_index("".join(col)) if col else 0
    return (max(0, r), max(0, c))


def _xlsx_read_shared_strings(zipf: zipfile.ZipFile) -> List[str]:
    try:
        raw = zipf.read("xl/sharedStrings.xml")
    except KeyError:
        return []

    try:
        root = ET.fromstring(raw.decode("utf-8", "ignore"))
    except Exception:
        return []

    # namespace 무시하고 <si> 안의 모든 <t> 텍스트를 연결
    out: List[str] = []
    for si in root.findall(".//{*}si"):
        parts: List[str] = []
        for t in si.findall(".//{*}t"):
            if t.text:
                parts.append(t.text)
        out.append(unicodedata.normalize("NFKC", "".join(parts)))
    return out


def _xlsx_sheet_to_grid(zipf: zipfile.ZipFile, sheet_path: str, sst: List[str]) -> List[List[str]]:
    try:
        raw = zipf.read(sheet_path)
    except KeyError:
        return []

    try:
        root = ET.fromstring(raw.decode("utf-8", "ignore"))
    except Exception:
        return []

    cells: dict[Tuple[int, int], str] = {}
    max_r = -1
    max_c = -1

    for c in root.findall(".//{*}sheetData/{*}row/{*}c"):
        ref = c.attrib.get("r") or ""
        r, col = _xlsx_cell_ref_to_rc(ref)
        t = (c.attrib.get("t") or "").strip()

        v = ""
        if t == "s":
            v_el = c.find("{*}v")
            try:
                idx = int((v_el.text or "").strip()) if v_el is not None else -1
            except Exception:
                idx = -1
            if 0 <= idx < len(sst):
                v = sst[idx]
        elif t == "inlineStr":
            # <c t="inlineStr"><is><t>...</t></is></c>
            is_el = c.find("{*}is")
            if is_el is not None:
                parts = []
                for t_el in is_el.findall(".//{*}t"):
                    if t_el.text:
                        parts.append(t_el.text)
                v = unicodedata.normalize("NFKC", "".join(parts))
        else:
            v_el = c.find("{*}v")
            v = (v_el.text or "") if v_el is not None else ""
            v = unicodedata.normalize("NFKC", v)

        v = (v or "").strip()
        if v != "":
            cells[(r, col)] = v
            if r > max_r:
                max_r = r
            if col > max_c:
                max_c = col

    if max_r < 0 or max_c < 0:
        return []

    grid: List[List[str]] = []
    for r in range(max_r + 1):
        row = []
        for cidx in range(max_c + 1):
            row.append(cells.get((r, cidx), ""))
        grid.append(row)
    return grid


def _grid_to_tsv(grid: List[List[str]], *, max_rows: int = 200, max_cols: int = 60) -> str:
    if not grid:
        return ""
    # 전체 기준으로 trailing empty col/row trim
    max_c = -1
    max_r = -1
    for r, row in enumerate(grid):
        for c, v in enumerate(row):
            if str(v).strip():
                max_r = max(max_r, r)
                max_c = max(max_c, c)

    if max_r < 0 or max_c < 0:
        return ""

    max_r = min(max_r, max_rows - 1)
    max_c = min(max_c, max_cols - 1)

    lines: List[str] = []
    for r in range(max_r + 1):
        row = grid[r]
        cells = [str(row[c]).replace("\t", " ").strip() for c in range(max_c + 1)]
        lines.append("\t".join(cells).rstrip())

    # 너무 큰 시트는 안내 라인
    truncated = (max_r + 1 < len(grid)) or any(len(r) > max_c + 1 for r in grid)
    if truncated:
        lines.append("")
        lines.append(f"(표 일부만 표시: rows<= {max_rows}, cols<= {max_cols})")

    return "\n".join(lines).strip()


def xlsx_table_text(zipf: zipfile.ZipFile) -> str:
    # sheet1..n을 TSV로 구성 (UI의 normalizeTsvTablesToMarkdown가 표로 렌더링)
    sst = _xlsx_read_shared_strings(zipf)
    sheet_names = sorted(
        [n for n in zipf.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
    )

    blocks: List[str] = []
    for sp in sheet_names:
        grid = _xlsx_sheet_to_grid(zipf, sp, sst)
        tsv = _grid_to_tsv(grid)
        if not tsv.strip():
            continue
        # 시트 구분: 표 블록 앞에 라벨 1줄 (표 파싱과 충돌하지 않도록 탭 없는 단일 라인)
        blocks.append(f"[{sp.split('/')[-1]}]")
        blocks.append(tsv)
        blocks.append("")

    return "\n".join(blocks).strip()


def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        tsv = xlsx_table_text(zipf)
        # fallback: 테이블 재구성이 실패하면 기존 텍스트 추출 사용
        txt = tsv if tsv.strip() else xlsx_text(zipf)
    return {"full_text": txt, "markdown": txt, "pages": [{"page": 1, "text": txt}]}


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