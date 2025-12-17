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


# 환경변수 bool 파싱
def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


# 환경변수 float 파싱
def _env_float(key: str, default: float) -> float:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


# compile_rules 결과(튜플/객체) 공통 순회
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


# 특정 룰 하나만 찾아서 (rx, need_valid, validator) 반환
def _get_rule(comp, name: str):
    for rule, rx, need_valid, validator in _iter_comp(comp):
        if rule == name:
            return rx, need_valid, validator
    return None, True, None


# validator 호출(시그니처 차이 대비)
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


def _candidate_texts(text: str, extra: Optional[str] = None) -> List[str]:
    t0 = (text or "").strip()
    if not t0:
        return []

    out: List[str] = []
    seen = set()

    def _add(x: str):
        x = (x or "").strip()
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

    for m in re.finditer(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", t0):
        _add(m.group(0))

    for m in re.finditer(r"\b[A-Z][0-9]{7,9}\b", t_ns):
        _add(m.group(0))
    for m in re.finditer(r"\b[A-Z][0-9]{3}[A-Z][0-9]{4}\b", t_ns):
        _add(m.group(0))

    return out


# 후보 텍스트들을 룰(rx)로 매칭해서 (rule, value) 반환
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


# OCR block들을 y 기준으로 줄 단위로 그룹핑
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


# 이메일이 토큰으로 쪼개진 경우(예: "abc" "@" "x.com") 한 줄에서 합치기
def _merge_email_from_line_tokens(line: List[Dict[str, Any]], comp) -> List[Dict[str, Any]]:
    rx, need_valid, validator = _get_rule(comp, "email")
    if rx is None:
        return []

    texts = [str(b.get("text") or "").strip() for b in line]
    if not any("@" in t for t in texts):
        return []

    joined_all = "".join(t.replace(" ", "") for t in texts if t)
    cand = [joined_all]

    for i, t in enumerate(texts):
        if "@" not in t:
            continue
        for L in (1, 2, 3):
            for R in (1, 2, 3):
                s = "".join(texts[max(0, i - L): min(len(texts), i + R + 1)])
                s = s.replace(" ", "")
                cand.append(s)

    best = None
    for s in cand:
        m = rx.search(s)
        if not m:
            continue
        val = m.group(0)
        if need_valid and not _run_validator(val, validator):
            continue
        best = val
        break

    if not best:
        m2 = re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", joined_all)
        if m2:
            val = m2.group(0)
            if (not need_valid) or _run_validator(val, validator):
                best = val

    if not best:
        return []

    idx_at = None
    for i, t in enumerate(texts):
        if "@" in t:
            idx_at = i
            break
    if idx_at is None:
        return []

    bx0, by0, bx1, by1 = _block_bbox(line[idx_at])
    for b in line[idx_at:]:
        x0, y0, x1, y1 = _block_bbox(b)
        bx0, by0, bx1, by1 = _union_bbox((bx0, by0, bx1, by1), (x0, y0, x1, y1))

    return [{"text": best, "normalized": best, "bbox": [bx0, by0, bx1, by1]}]


# 카드번호가 여러 토큰/여러 줄로 나뉜 경우 숫자 그룹을 합쳐서 후보 생성
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


# bbox+text 기준으로 OCR 블록 중복 제거
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
            ob = o.get("bbox") or [0, 0, 0, 0]
            try:
                ox0, oy0, ox1, oy1 = map(float, ob)
            except Exception:
                continue
            if abs(x0 - ox0) < 3 and abs(y0 - oy0) < 3 and abs(x1 - ox1) < 3 and abs(y1 - oy1) < 3:
                if t == ot:
                    dup = True
                    break
        if not dup:
            out.append(b)
    return out


# OCR 1회 실행(옵션에 따라 전처리/업스케일 적용)
def _ocr_pass(
    img: Image.Image,
    min_conf: float,
    gpu: bool = False,
    autocontrast: bool = False,
    upscale: float = 1.0,
    sharpen: bool = False,
):
    x = img
    if upscale and upscale > 1.01:
        w = int(x.width * upscale)
        h = int(x.height * upscale)
        x = x.resize((w, h), resample=Image.BICUBIC)
    if autocontrast:
        g = x.convert("L")
        g = ImageOps.autocontrast(g)
        x = g.convert("RGB")
    if sharpen:
        x = x.filter(ImageFilter.UnsharpMask(radius=2, percent=150, threshold=2))
    return easyocr_blocks(x, min_conf=min_conf, gpu=gpu), (x.width / img.width, x.height / img.height)

def _scale_bbox(bbox, sx: float, sy: float):
    x0, y0, x1, y1 = bbox
    return [x0 / sx, y0 / sy, x1 / sx, y1 / sy]


# 이미지에서 OCR 후 민감정보 후보 블록들을 룰로 매칭하여 반환
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

    gpu = _env_bool(f"{env_prefix}_OCR_GPU", False)

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
        print(f"[{env_prefix}] OCR blocks=", len(blocks), "image=", filename)

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

    # LLM 분류(kind) -> 룰 후보군 제한(없으면 전체 룰로 재시도)
    kind_to_rules = {
        "email": ["email"],
        "phone": ["phone_mobile", "phone_city"],
        "card": ["card"],
        "id": ["rrn", "fgn", "passport", "driver_license"],
    }

    matched: List[Dict[str, Any]] = []

    for b in llm_blocks:
        txt = str(b.get("normalized") or b.get("text") or "").strip()
        if not txt:
            continue

        llm_kind = (b.get("kind") or "none").strip().lower()
        candidates = kind_to_rules.get(llm_kind)

        rule, val = _match_text_to_rules(txt, comp, candidates=candidates) if candidates else (None, None)
        if rule is None:
            rule, val = _match_text_to_rules(txt, comp, candidates=None)

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


# 이미지 바이트를 받아 OCR로 민감정보 bbox를 마스킹하고 (bytes, hit) 또는 bytes 반환
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
        os.environ[f"{env_prefix}_OCR_GPU"] = "1" if gpu else "0"

    pad_y = _env_float(f"{env_prefix}_OCR_PAD_Y", 0.4)
    pad_x_left = _env_float(f"{env_prefix}_OCR_PAD_XL", 0.4)
    pad_x_right = _env_float(f"{env_prefix}_OCR_PAD_XR", 1.0)

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
        try:
            x0, y0, x1, y1 = b.get("bbox", [0, 0, 0, 0])
            x0 = float(x0)
            y0 = float(y0)
            x1 = float(x1)
            y1 = float(y1)
        except Exception:
            continue

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
                repr(str(b.get("value") or b.get("text") or "")[:120]),
                "bbox=",
                b.get("bbox"),
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
