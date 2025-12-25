from __future__ import annotations

import io
import os
import re
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from PIL import Image, ImageDraw, ImageOps, ImageFilter

try:
    from server.modules.ocr_module import easyocr_blocks
    from server.modules.ocr_qwen_post import classify_blocks_with_qwen
except Exception:
    from .ocr_module import easyocr_blocks
    from .ocr_qwen_post import classify_blocks_with_qwen


# 이메일 완화 정규식 (OCR 오타/기호 변형 대응)
# - @가 전각(＠)일 수 있음
# - dot이 '.' 말고 '·', '。', ',' 등으로 나올 수 있음
EMAIL_RX_RELAXED = re.compile(
    r"[A-Za-z0-9._%+\-]+[@＠][A-Za-z0-9.\-]+(?:[\.。,·。][A-Za-z]{2,})",
    re.IGNORECASE,
)


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


def _env_int(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(float(v))
    except Exception:
        return default


def _torch_cuda_available() -> bool:
    try:
        import torch  # type: ignore
        return bool(torch.cuda.is_available())
    except Exception:
        return False


def _iter_comp(comp):
    for ent in comp:
        if isinstance(ent, (list, tuple)):
            rule = ent[0] if len(ent) > 0 else "unknown"
            rx = ent[1] if len(ent) > 1 else None
            need_valid = bool(ent[2]) if len(ent) > 2 else True
            validator = ent[4] if len(ent) > 4 else None
            yield rule, rx, need_valid, validator
        else:
            rule = getattr(ent, "name", getattr(ent, "rule", "unknown"))
            rx = getattr(ent, "rx", None)
            need_valid = bool(getattr(ent, "need_valid", True))
            validator = getattr(ent, "validator", None)
            yield rule, rx, need_valid, validator


def _get_rule(comp, name: str):
    for rule, rx, need_valid, validator in _iter_comp(comp):
        if rule == name:
            return rx, need_valid, validator
    return None, True, None


def _run_validator(value: str, validator) -> bool:
    if not callable(validator):
        return True
    try:
        return bool(validator(value))
    except TypeError:
        try:
            return bool(validator(value, None))
        except Exception:
            return False
    except Exception:
        return False


def _digits(s: str) -> str:
    return re.sub(r"\D+", "", s or "")


def _image_fill_rgba(fill: str):
    f = (fill or "black").strip().lower()
    return (0, 0, 0, 255) if f == "black" else (255, 255, 255, 255)


def _union_bbox(a, b):
    ax0, ay0, ax1, ay1 = a
    bx0, by0, bx1, by1 = b
    return (min(ax0, bx0), min(ay0, by0), max(ax1, bx1), max(ay1, by1))


def _normalize_ocr_text(s: str) -> str:
    if not s:
        return ""
    return (
        s.replace("＠", "@")
        .replace("。", ".")
        .replace("·", ".")
        .replace("，", ",")
        .replace("／", "/")
    )


def _fallback_find_email(text: str) -> Optional[str]:
    t = _normalize_ocr_text(text or "")
    if not t:
        return None
    m = EMAIL_RX_RELAXED.search(t)
    if not m:
        return None
    return m.group(0)


def _candidate_texts(text: str, extra: Optional[str] = None) -> List[str]:
    t0 = _normalize_ocr_text((text or "").strip())
    if not t0:
        return []

    out: List[str] = []
    seen = set()

    def _add(x: str):
        x = _normalize_ocr_text((x or "").strip())
        if not x or x in seen:
            return
        seen.add(x)
        out.append(x)

    _add(t0)
    if extra:
        _add(extra)

    for sep in (":", "："):
        if sep in t0:
            _add(t0.split(sep, 1)[1].strip())

    t_ns = t0.replace(" ", "")
    _add(t_ns)
    _add(t_ns.replace("|", "").replace("I", "1"))

    for tok in re.split(r"[\s,;()\[\]{}<>\"'“”‘’]+", t0):
        _add(tok)
    for tok in re.split(r"[:：=|]+", t0):
        _add(tok)

    m = EMAIL_RX_RELAXED.search(t0)
    if m:
        _add(m.group(0))

    for m in re.finditer(r"\b[A-Z][0-9]{7,9}\b", t_ns):
        _add(m.group(0))
    for m in re.finditer(r"\b[A-Z][0-9]{3}[A-Z][0-9]{4}\b", t_ns):
        _add(m.group(0))

    return out


def _match_text_to_rules(
    text: str,
    comp,
    candidates: Optional[List[str]] = None,
    extra_candidate: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    for t in _candidate_texts(text, extra=extra_candidate):
        for rule, rx, need_valid, validator in _iter_comp(comp):
            if candidates is not None and rule not in candidates:
                continue
            if rx is None:
                continue
            m = rx.search(t)
            if not m:
                continue
            val = m.group(0)
            if need_valid and not _run_validator(val, validator):
                continue
            return rule, val
    return None, None


def _block_bbox(b: Dict[str, Any]):
    bb = b.get("bbox") or [0, 0, 0, 0]
    x0, y0, x1, y1 = map(float, bb)
    return x0, y0, x1, y1


def _y_center(b):
    x0, y0, x1, y1 = _block_bbox(b)
    return (y0 + y1) * 0.5


def _x_center(b):
    x0, y0, x1, y1 = _block_bbox(b)
    return (x0 + x1) * 0.5


def _group_lines(blocks: List[Dict[str, Any]], y_tol: float = 10.0) -> List[List[Dict[str, Any]]]:
    if not blocks:
        return []
    blocks_sorted = sorted(blocks, key=lambda b: (_y_center(b), _x_center(b)))
    lines: List[List[Dict[str, Any]]] = []
    for b in blocks_sorted:
        yc = _y_center(b)
        placed = False
        for line in lines:
            lyc = sum(_y_center(x) for x in line) / max(1, len(line))
            if abs(yc - lyc) <= y_tol:
                line.append(b)
                placed = True
                break
        if not placed:
            lines.append([b])
    for line in lines:
        line.sort(key=lambda b: _block_bbox(b)[0])
    return lines


def _merge_email_from_line_tokens(line: List[Dict[str, Any]], comp) -> List[Dict[str, Any]]:
    texts = [_normalize_ocr_text(str(b.get("text") or "").strip()) for b in line]
    if not any(("@" in t) for t in texts):
        if not any(("＠" in (b.get("text") or "")) for b in line):
            return []

    joined = ""
    spans: List[Tuple[int, int]] = []
    for t in texts:
        t2 = (t or "").replace(" ", "")
        s = len(joined)
        joined += t2
        e = len(joined)
        spans.append((s, e))

    rx, need_valid, validator = _get_rule(comp, "email")
    m = rx.search(joined) if rx else None
    if m:
        val = m.group(0)
        if need_valid and not _run_validator(val, validator):
            return []
        ms, me = m.start(), m.end()
    else:
        m2 = EMAIL_RX_RELAXED.search(joined)
        if not m2:
            return []
        val = m2.group(0)
        ms, me = m2.start(), m2.end()

    hit_idxs: List[int] = []
    for i, (s, e) in enumerate(spans):
        if e <= ms or s >= me:
            continue
        hit_idxs.append(i)
    if not hit_idxs:
        return []

    bx0, by0, bx1, by1 = _block_bbox(line[hit_idxs[0]])
    for i in hit_idxs[1:]:
        bx0, by0, bx1, by1 = _union_bbox((bx0, by0, bx1, by1), _block_bbox(line[i]))

    return [{"text": val, "normalized": val, "bbox": [bx0, by0, bx1, by1]}]


def _merge_cards_from_digit_groups(
    lines: List[List[Dict[str, Any]]],
    comp,
    y_next_tol: float = 120.0,
) -> List[Dict[str, Any]]:
    rx, need_valid, validator = _get_rule(comp, "card")
    if rx is None and validator is None:
        return []

    def _ok_card(digits: str) -> bool:
        if len(digits) < 13 or len(digits) > 19:
            return False
        if need_valid and callable(validator):
            return _run_validator(digits, validator)
        if rx is not None:
            return bool(rx.search(digits))
        return True

    out: List[Dict[str, Any]] = []

    line_tokens: List[List[Tuple[Dict[str, Any], str]]] = []
    for line in lines:
        toks: List[Tuple[Dict[str, Any], str]] = []
        for b in line:
            t = str(b.get("text") or "").strip()
            d = _digits(t)
            if not d:
                continue
            if 2 <= len(d) <= 4 or 8 <= len(d) <= 15:
                toks.append((b, d))
        line_tokens.append(toks)

    for toks in line_tokens:
        if not toks:
            continue

        digits_join = "".join(d for _, d in toks if 2 <= len(d) <= 4)
        if _ok_card(digits_join):
            bx0, by0, bx1, by1 = _block_bbox(toks[0][0])
            for b, _d in toks[1:]:
                bx0, by0, bx1, by1 = _union_bbox((bx0, by0, bx1, by1), _block_bbox(b))
            out.append({"text": digits_join, "normalized": digits_join, "bbox": [bx0, by0, bx1, by1]})

        chunks = [d for _, d in toks]
        for i in range(len(chunks)):
            for j in range(i + 1, min(len(chunks), i + 4)):
                comb = chunks[i] + "".join(chunks[i + 1: j + 1])
                if _ok_card(comb):
                    bx0, by0, bx1, by1 = _block_bbox(toks[i][0])
                    for k in range(i + 1, j + 1):
                        bx0, by0, bx1, by1 = _union_bbox((bx0, by0, bx1, by1), _block_bbox(toks[k][0]))
                    out.append({"text": comb, "normalized": comb, "bbox": [bx0, by0, bx1, by1]})

    for idx in range(len(lines) - 1):
        top = line_tokens[idx]
        bot = line_tokens[idx + 1]
        if not top or not bot:
            continue

        try:
            top_y = sum(_y_center(b) for b, _ in top) / len(top)
            bot_y = sum(_y_center(b) for b, _ in bot) / len(bot)
        except Exception:
            continue
        if bot_y - top_y > y_next_tol:
            continue

        top_digits = "".join(d for _, d in top)
        bot_groups = [d for _, d in bot if 2 <= len(d) <= 6]
        if not bot_groups:
            continue
        bot_digits = "".join(bot_groups)

        comb = top_digits + bot_digits
        if _ok_card(comb):
            bx0, by0, bx1, by1 = _block_bbox(top[0][0])
            for b, _d in top[1:]:
                bx0, by0, bx1, by1 = _union_bbox((bx0, by0, bx1, by1), _block_bbox(b))
            for b, _d in bot:
                bx0, by0, bx1, by1 = _union_bbox((bx0, by0, bx1, by1), _block_bbox(b))
            out.append({"text": comb, "normalized": comb, "bbox": [bx0, by0, bx1, by1]})

    return out


def _dedup_blocks(blocks: List[dict]) -> List[dict]:
    out: List[dict] = []
    for b in blocks:
        t = str(b.get("text") or "").strip()
        bb = b.get("bbox") or [0, 0, 0, 0]
        try:
            x0, y0, x1, y1 = map(float, bb)
        except Exception:
            out.append(b)
            continue

        dup = False
        for o in out:
            ot = str(o.get("text") or "").strip()
            obb = o.get("bbox") or [0, 0, 0, 0]
            try:
                ox0, oy0, ox1, oy1 = map(float, obb)
            except Exception:
                continue

            if t == ot:
                if abs(x0 - ox0) < 2 and abs(y0 - oy0) < 2 and abs(x1 - ox1) < 2 and abs(y1 - oy1) < 2:
                    dup = True
                    break
        if not dup:
            out.append(b)
    return out


def _scale_bbox(bb, sx: float, sy: float):
    x0, y0, x1, y1 = bb
    return [x0 / sx, y0 / sy, x1 / sx, y1 / sy]


def _ocr_pass(
    image: Image.Image,
    conf: float,
    *,
    gpu: bool = False,
    autocontrast: bool = False,
    upscale: float = 1.0,
    sharpen: bool = False,
) -> Tuple[List[Dict[str, Any]], Tuple[float, float]]:
    img = image
    sx = 1.0
    sy = 1.0

    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    if autocontrast:
        try:
            img = ImageOps.autocontrast(img)
        except Exception:
            pass

    if sharpen:
        try:
            img = img.filter(ImageFilter.SHARPEN)
        except Exception:
            pass

    if upscale and upscale != 1.0:
        try:
            w = int(img.width * float(upscale))
            h = int(img.height * float(upscale))
            if w > 0 and h > 0:
                img = img.resize((w, h), resample=Image.BICUBIC)
                sx = float(upscale)
                sy = float(upscale)
        except Exception:
            pass

    blocks = easyocr_blocks(img, min_conf=conf, gpu=gpu) or []
    return blocks, (sx, sy)


def _char_weight(ch: str) -> float:
    o = ord(ch)
    if ch.isspace():
        return 0.18
    if (0xAC00 <= o <= 0xD7A3) or (0x1100 <= o <= 0x11FF) or (0x3130 <= o <= 0x318F):
        return 1.05
    if 0x4E00 <= o <= 0x9FFF:
        return 1.00
    if "0" <= ch <= "9":
        return 0.62
    if ("A" <= ch <= "Z") or ("a" <= ch <= "z"):
        return 0.68
    if ch in ":：-‐–—._/\\|()[]{},@":
        return 0.28
    return 0.55


def _weighted_prefix(text: str) -> List[float]:
    pref = [0.0]
    s = 0.0
    for ch in text:
        s += _char_weight(ch)
        pref.append(s)
    return pref


def _shrink_bbox_by_substring(block_text: str, value: str, bbox: List[float]) -> List[float]:
    raw_t = _normalize_ocr_text(block_text or "")
    raw_v = _normalize_ocr_text(value or "")
    if not raw_t or not raw_v:
        return bbox

    try:
        x0, y0, x1, y1 = map(float, bbox)
    except Exception:
        return bbox
    w = max(1.0, x1 - x0)

    def _compact_digits_with_map(s: str) -> Tuple[str, List[int]]:
        out_chars: List[str] = []
        idx_map: List[int] = []
        for i, ch in enumerate(s):
            if "0" <= ch <= "9":
                out_chars.append(ch)
                idx_map.append(i)
        return "".join(out_chars), idx_map

    def _compact_nospace_with_map(s: str) -> Tuple[str, List[int]]:
        out_chars: List[str] = []
        idx_map: List[int] = []
        for i, ch in enumerate(s):
            if ch.isspace():
                continue
            out_chars.append(ch)
            idx_map.append(i)
        return "".join(out_chars), idx_map

    v_digits = _digits(raw_v)
    if "@" in raw_v or "@" in raw_t:
        mode = "email"
    elif len(v_digits) >= 6 and (len(v_digits) / max(len(raw_v), 1)) >= 0.6:
        mode = "digits"
    else:
        mode = "default"

    if mode == "default":
        idx = raw_t.find(raw_v)
        if idx >= 0:
            start_idx = idx
            end_idx = idx + len(raw_v)
        else:
            t2, mp = _compact_nospace_with_map(raw_t)
            v2 = re.sub(r"\s+", "", raw_v)
            j = t2.find(v2) if v2 else -1
            if j < 0:
                return bbox
            start_idx = mp[j]
            end_idx = mp[j + len(v2) - 1] + 1

    elif mode == "digits":
        t2, mp = _compact_digits_with_map(raw_t)
        v2 = v_digits
        if not t2 or not v2:
            return bbox
        j = t2.find(v2)
        if j < 0:
            return bbox
        start_idx = mp[j]
        end_idx = mp[j + len(v2) - 1] + 1

    else:  # email
        t2, mp = _compact_nospace_with_map(raw_t)
        v2 = re.sub(r"\s+", "", raw_v)
        if not t2 or not v2:
            return bbox
        j = t2.find(v2)
        if j < 0:
            # raw_t 안에서 완화 regex로 다시 span 잡기
            m = EMAIL_RX_RELAXED.search(raw_t)
            if not m:
                return bbox
            start_idx, end_idx = m.start(), m.end()
        else:
            start_idx = mp[j]
            end_idx = mp[j + len(v2) - 1] + 1

    pref = _weighted_prefix(raw_t)
    total = max(1e-6, pref[-1])
    start_ratio = pref[max(0, min(start_idx, len(raw_t)))] / total
    end_ratio = pref[max(0, min(end_idx, len(raw_t)))] / total

    nx0 = x0 + w * start_ratio
    nx1 = x0 + w * end_ratio

    if nx1 - nx0 < 1.0:
        return bbox

    return [nx0, y0, nx1, y1]


def _tighten_overwide_bbox(text: str, bbox: List[float], *, char_px_factor: float, slack: float) -> List[float]:
    try:
        x0, y0, x1, y1 = map(float, bbox)
    except Exception:
        return bbox

    w = max(1.0, x1 - x0)
    h = max(1.0, y1 - y0)

    t = _normalize_ocr_text(text or "").strip()
    if not t:
        return bbox

    total_weight = 0.0
    for ch in t:
        total_weight += _char_weight(ch)

    expected_w = max(8.0, h * char_px_factor * total_weight)
    limit_w = expected_w * (1.0 + max(0.0, slack))

    # 너무 과도하게 넓을 때만 줄임
    if w <= limit_w:
        return bbox

    cx = (x0 + x1) * 0.5
    half = limit_w * 0.5
    nx0 = cx - half
    nx1 = cx + half
    return [nx0, y0, nx1, y1]


def detect_sensitive_ocr_blocks(
    image: Image.Image,
    *,
    env_prefix: str = "DOCX",
    filename: str = "",
    logger: Optional[logging.Logger] = None,
    comp=None,
) -> List[Dict[str, Any]]:
    if comp is None:
        from server.modules.common import compile_rules
        comp = compile_rules()

    log = logger or logging.getLogger("ocr_image_redactor")

    use_llm = _env_bool(f"{env_prefix}_OCR_LLM", _env_bool(f"{env_prefix}_OCR_USE_LLM", True))
    debug = _env_bool(f"{env_prefix}_OCR_DEBUG", False)

    conf1 = _env_float(f"{env_prefix}_OCR_MINCONF", 0.30)
    conf2 = _env_float(f"{env_prefix}_OCR_MINCONF2", 0.05)
    conf3 = _env_float(f"{env_prefix}_OCR_MINCONF3", 0.01)

    pass2 = _env_bool(f"{env_prefix}_OCR_SECOND_PASS", True)
    pass3 = _env_bool(f"{env_prefix}_OCR_UPSCALE_PASS", True)
    upscale = _env_float(f"{env_prefix}_OCR_UPSCALE", 2.0)

    gpu_env = os.getenv(f"{env_prefix}_OCR_GPU")
    if gpu_env is None:
        gpu = _torch_cuda_available()  # 자동 감지
    else:
        gpu = _env_bool(f"{env_prefix}_OCR_GPU", False) and _torch_cuda_available()

    max_px_for_upscale = _env_int(f"{env_prefix}_OCR_MAX_PX_FOR_UPSCALE", 2200000)  # ~1920x1146 정도
    if (not gpu) and pass3:
        try:
            if (image.width * image.height) >= max_px_for_upscale:
                pass3 = False
        except Exception:
            pass

    line_y_tol = _env_float(f"{env_prefix}_OCR_LINE_YTOL", 12.0)
    card_nextline_tol = _env_float(f"{env_prefix}_OCR_CARD_NEXTLINE_TOL", 140.0)

    blocks_all: List[Dict[str, Any]] = []

    b1, (_sx1, _sy1) = _ocr_pass(image, conf1, gpu=gpu, autocontrast=False, upscale=1.0, sharpen=False)
    blocks_all += b1

    if pass2:
        b2, (_sx2, _sy2) = _ocr_pass(image, conf2, gpu=gpu, autocontrast=True, upscale=1.0, sharpen=True)
        blocks_all += b2

    if pass3:
        b3, (sx3, sy3) = _ocr_pass(image, conf3, gpu=gpu, autocontrast=True, upscale=upscale, sharpen=True)
        for bb in b3:
            try:
                x0, y0, x1, y1 = map(float, bb.get("bbox") or [0, 0, 0, 0])
                bb["bbox"] = _scale_bbox([x0, y0, x1, y1], sx3, sy3)
            except Exception:
                pass
        blocks_all += b3

    blocks = _dedup_blocks(blocks_all)
    if debug:
        print(f"[{env_prefix}] RAW OCR blocks=", len(blocks_all))
        print(f"[{env_prefix}] OCR blocks=", len(blocks), "image=", filename, "gpu=", gpu)

    if not blocks:
        return []

    lines = _group_lines(blocks, y_tol=line_y_tol)

    synthetic: List[Dict[str, Any]] = []
    for line in lines:
        synthetic += _merge_email_from_line_tokens(line, comp)
    synthetic += _merge_cards_from_digit_groups(lines, comp, y_next_tol=card_nextline_tol)

    for s in synthetic:
        s["conf"] = 0.0
        blocks.append(s)

    llm_blocks = blocks
    if use_llm:
        try:
            llm_blocks = classify_blocks_with_qwen(blocks)
        except Exception:
            llm_blocks = blocks

    kind_to_rules = {
        "email": ["email"],
        "phone": ["phone_mobile", "phone_city"],
        "card": ["card"],
        "id": ["rrn", "fgn", "passport", "driver_license"],
    }

    matched: List[Dict[str, Any]] = []

    for b in llm_blocks:
        txt_raw = str(b.get("normalized") or b.get("text") or "").strip()
        txt = _normalize_ocr_text(txt_raw)
        if not txt:
            continue

        llm_kind = (b.get("kind") or "none").strip().lower()
        candidates = kind_to_rules.get(llm_kind)

        rule, val = _match_text_to_rules(txt, comp, candidates=candidates) if candidates else (None, None)
        if rule is None:
            rule, val = _match_text_to_rules(txt, comp, candidates=None)

        # 이메일 강제 fallback
        if rule is None:
            em = _fallback_find_email(txt)
            if em:
                rule, val = "email", em

        if rule is None:
            continue

        bb = dict(b)
        bb["rule"] = rule
        bb["value"] = val or txt
        matched.append(bb)

    if debug:
        counts: Dict[str, int] = {}
        for m in matched:
            r = m.get("rule") or "unknown"
            counts[r] = counts.get(r, 0) + 1
        print(f"[{env_prefix}] OCR matched rules=", counts)

    return matched


def redact_image_bytes(
    image_bytes: bytes,
    comp=None,
    *,
    filename: str = "",
    env_prefix: str = "DOCX",
    logger: Optional[logging.Logger] = None,
    fill: str = "black",
    use_llm: Optional[bool] = None,
    min_conf: Optional[float] = None,
    gpu: Optional[bool] = None,
) -> Union[bytes, Tuple[bytes, int]]:
    want_tuple = comp is not None or bool(filename) or logger is not None or env_prefix != "DOCX"
    log = logger or logging.getLogger("ocr_image_redactor")

    debug = _env_bool(f"{env_prefix}_OCR_DEBUG", False)

    if use_llm is not None:
        os.environ[f"{env_prefix}_OCR_USE_LLM"] = "1" if use_llm else "0"
    if min_conf is not None:
        os.environ[f"{env_prefix}_OCR_MINCONF"] = str(min_conf)
    if gpu is not None:
        # gpu=True를 줘도 실제 CUDA 없으면 내부에서 자동 false로 떨어짐
        os.environ[f"{env_prefix}_OCR_GPU"] = "1" if gpu else "0"

    pad_y = _env_float(f"{env_prefix}_OCR_PAD_Y", 0.10)
    pad_x_left = _env_float(f"{env_prefix}_OCR_PAD_XL", 0.06)
    pad_x_right = _env_float(f"{env_prefix}_OCR_PAD_XR", 0.18)

    char_px_factor = _env_float(f"{env_prefix}_OCR_CHAR_PX_FACTOR", 0.55)
    overwide_slack = _env_float(f"{env_prefix}_OCR_OVERWIDE_SLACK", 0.35)

    extra_x_sensitive = _env_float(f"{env_prefix}_OCR_EXTRA_X_SENSITIVE", 0.12)  # 픽셀 단위가 아니라 "높이*h"로 적용
    extra_x_card = _env_float(f"{env_prefix}_OCR_EXTRA_X_CARD", 0.18)
    extra_x_email = _env_float(f"{env_prefix}_OCR_EXTRA_X_EMAIL", 0.16)

    if debug:
        print(f"[{env_prefix}] OCR start image=", filename, "size=", len(image_bytes))

    try:
        img0 = Image.open(io.BytesIO(image_bytes))
        img0.load()
    except Exception as e:
        if debug:
            print(f"[{env_prefix}] OCR open failed image=", filename, "err=", repr(e))
        return (image_bytes, 0) if want_tuple else image_bytes

    fmt = (img0.format or "").upper() or "PNG"

    if fmt == "PNG":
        img = img0.convert("RGBA") if img0.mode != "RGBA" else img0
    else:
        if img0.mode not in ("RGB", "RGBA"):
            img = img0.convert("RGB")
        elif img0.mode == "RGBA":
            img = img0.convert("RGB")
        else:
            img = img0

    if comp is None:
        from server.modules.common import compile_rules
        comp = compile_rules()

    matched = detect_sensitive_ocr_blocks(
        img,
        env_prefix=env_prefix,
        filename=filename,
        logger=log,
        comp=comp,
    )

    if not matched:
        if debug:
            print(f"[{env_prefix}] OCR end image=", filename, "hits=0")
        return (image_bytes, 0) if want_tuple else image_bytes

    draw = ImageDraw.Draw(img)
    fill_rgba = _image_fill_rgba(fill)
    if img.mode == "RGB":
        fill_rgba = fill_rgba[:3]

    hit = 0
    rule_counts: Dict[str, int] = {}

    for b in matched:
        bbox0 = b.get("bbox", [0, 0, 0, 0])

        txt_full = _normalize_ocr_text(str(b.get("text") or b.get("normalized") or ""))
        val = _normalize_ocr_text(str(b.get("value") or ""))

        # 1) 기본: value substring으로 bbox를 줄이기
        bbox = _shrink_bbox_by_substring(txt_full, val, bbox0)

        # 2) 통가림 완화: bbox가 과도하게 넓으면 텍스트 길이 기반으로 폭을 줄임
        bbox = _tighten_overwide_bbox(val or txt_full, bbox, char_px_factor=char_px_factor, slack=overwide_slack)

        try:
            x0, y0, x1, y1 = bbox
            x0 = float(x0)
            y0 = float(y0)
            x1 = float(x1)
            y1 = float(y1)
        except Exception:
            continue

        h = max(1.0, y1 - y0)

        # 3) "전체적으로 길게" + "민감항목은 더 길게"
        rule = (b.get("rule") or "").strip().lower()
        extra = extra_x_sensitive
        if rule == "card":
            extra = extra_x_card
        elif rule == "email":
            extra = extra_x_email

        # extra는 "높이 비례 픽셀"로 가로를 추가 연장
        x0 = x0 - (h * extra * 0.45)
        x1 = x1 + (h * extra * 1.00)

        # 4) 패딩 적용
        x0 = max(0.0, x0 - pad_x_left)
        y0 = max(0.0, y0 - pad_y)
        x1 = min(float(img.width), x1 + pad_x_right)
        y1 = min(float(img.height), y1 + pad_y)

        if x1 - x0 < 1.0 or y1 - y0 < 1.0:
            continue

        draw.rectangle([x0, y0, x1, y1], fill=fill_rgba)
        hit += 1

        r = b.get("rule") or "unknown"
        rule_counts[r] = rule_counts.get(r, 0) + 1

        if debug:
            print(
                f"[{env_prefix}] OCR HIT",
                "rule=",
                r,
                "text=",
                repr((val or str(b.get("text") or ""))[:120]),
                "bbox=",
                bbox0,
                "rect=",
                (x0, y0, x1, y1),
            )

    if hit <= 0:
        return (image_bytes, 0) if want_tuple else image_bytes

    out = io.BytesIO()
    try:
        if fmt in ("JPG", "JPEG"):
            img.save(out, format="JPEG", quality=95, optimize=True)
        elif fmt == "BMP":
            img.save(out, format="BMP")
        else:
            img.save(out, format="PNG")
    except Exception:
        return (image_bytes, 0) if want_tuple else image_bytes

    red = out.getvalue()

    if debug:
        print(
            f"[{env_prefix}] OCR end image=",
            filename,
            "in=",
            len(image_bytes),
            "out=",
            len(red),
            "changed=",
            red != image_bytes,
            "hit=",
            hit,
            "rules=",
            rule_counts,
        )

    return (red, hit) if want_tuple else red
