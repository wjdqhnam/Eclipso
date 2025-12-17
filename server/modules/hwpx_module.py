from __future__ import annotations
import io, re, zipfile, logging, os
from typing import List, Tuple, Optional, Dict, Any

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

# OCR 추출/후처리
try:
    from .ocr_module import easyocr_blocks
    from .ocr_qwen_post import classify_blocks_with_qwen
except Exception:
    from server.modules.ocr_module import easyocr_blocks
    from server.modules.ocr_qwen_post import classify_blocks_with_qwen

from PIL import Image, ImageDraw, ImageOps, ImageFilter


log = logging.getLogger("xml_redaction")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] xml_redaction: %(message)s"))
    log.addHandler(_h)
log.setLevel(logging.INFO)

_CURRENT_SECRETS: List[str] = []
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp")


def set_hwpx_secrets(values: List[str] | None):
    # OLE size-preserve 마스킹에서 쓰는 secrets 목록
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))


def _env_bool(key: str, default: bool) -> bool:
    # env flag 읽기
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _env_float(key: str, default: float) -> float:
    # env float 읽기
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


def _iter_comp(comp):
    # compile_rules 결과를 (rule, rx, need_valid, validator)로 통일
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
    # 특정 rule의 rx/validator 조회
    for rule, rx, need_valid, validator in _iter_comp(comp):
        if rule == name:
            return rx, need_valid, validator
    return None, True, None


def _run_validator(value: str, validator) -> bool:
    # validator 호출(시그니처 차이 허용)
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
    # 숫자만 추출
    return re.sub(r"\D+", "", s or "")


def _image_fill_rgba(fill: str):
    # 마스킹 색상(RGBA)
    f = (fill or "black").strip().lower()
    return (0, 0, 0, 255) if f == "black" else (255, 255, 255, 255)


def _union_bbox(a, b):
    # bbox union
    ax0, ay0, ax1, ay1 = a
    bx0, by0, bx1, by1 = b
    return (min(ax0, bx0), min(ay0, by0), max(ax1, bx1), max(ay1, by1))


def _candidate_texts(text: str) -> List[str]:
    # 룰 매칭용 후보 텍스트 변형 생성
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


def _match_text_to_rules(text: str, comp, candidates: Optional[List[str]] = None):
    # 텍스트를 룰(rx/validator)로 매칭
    for t in _candidate_texts(text):
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
    # block bbox 읽기
    bb = b.get("bbox") or [0, 0, 0, 0]
    x0, y0, x1, y1 = map(float, bb)
    return x0, y0, x1, y1


def _y_center(b):
    # bbox y center
    x0, y0, x1, y1 = _block_bbox(b)
    return (y0 + y1) * 0.5


def _x_center(b):
    # bbox x center
    x0, y0, x1, y1 = _block_bbox(b)
    return (x0 + x1) * 0.5


def _group_lines(blocks: List[Dict[str, Any]], y_tol: float = 10.0) -> List[List[Dict[str, Any]]]:
    # OCR blocks를 라인 단위로 클러스터링
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
    # 라인 토큰을 합쳐 email synthetic block 생성
    rx, need_valid, validator = _get_rule(comp, "email")
    if rx is None:
        return []

    merged: List[Dict[str, Any]] = []

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

    merged.append({"text": best, "normalized": best, "bbox": [bx0, by0, bx1, by1]})
    return merged


def _merge_cards_from_digit_groups(lines: List[List[Dict[str, Any]]], comp, y_next_tol: float = 120.0) -> List[Dict[str, Any]]:
    # 숫자 토큰을 합쳐 card synthetic block 생성(동일 라인/다음 라인)
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
        toks = []
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
                comb = chunks[i] + "".join(chunks[i + 1:j + 1])
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
    # 좌표+텍스트 기준 중복 제거
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


def _ocr_pass(
    img: Image.Image,
    min_conf: float,
    gpu: bool = False,
    autocontrast: bool = False,
    upscale: float = 1.0,
    sharpen: bool = False,
):
    # OCR pass(전처리 옵션 포함)
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
    # 업스케일된 bbox를 원본 스케일로 환산
    x0, y0, x1, y1 = bbox
    return [x0 / sx, y0 / sy, x1 / sx, y1 / sy]


def _redact_image_bytes(image_bytes: bytes, comp, *, filename: str = "?") -> Tuple[bytes, int]:
    # 이미지 OCR → 룰 매칭 → bbox 마스킹
    ocr_use_llm = _env_bool("HWPX_OCR_USE_LLM", True)
    ocr_debug = _env_bool("HWPX_OCR_DEBUG", False)

    conf1 = _env_float("HWPX_OCR_MIN_CONF", 0.30)
    conf2 = _env_float("HWPX_OCR_MIN_CONF2", 0.05)
    conf3 = _env_float("HWPX_OCR_MIN_CONF3", 0.01)

    pass2 = _env_bool("HWPX_OCR_SECOND_PASS", True)
    pass3 = _env_bool("HWPX_OCR_UPSCALE_PASS", True)
    upscale = _env_float("HWPX_OCR_UPSCALE", 2.0)

    ocr_fill = os.getenv("HWPX_OCR_FILL", "black") or "black"

    pad_y = _env_float("HWPX_OCR_PAD_Y", 0.4)
    pad_x_left = _env_float("HWPX_OCR_PAD_XL", 0.4)
    pad_x_right = _env_float("HWPX_OCR_PAD_XR", 1.0)

    line_y_tol = _env_float("HWPX_OCR_LINE_YTOL", 12.0)
    card_nextline_tol = _env_float("HWPX_OCR_CARD_NEXTLINE_TOL", 140.0)

    try:
        img0 = Image.open(io.BytesIO(image_bytes))
        img0.load()
    except Exception:
        return image_bytes, 0

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

    blocks_all: List[Dict[str, Any]] = []

    b1, (_sx1, _sy1) = _ocr_pass(img, conf1, gpu=False, autocontrast=False, upscale=1.0, sharpen=False)
    blocks_all += b1

    if pass2:
        b2, (_sx2, _sy2) = _ocr_pass(img, conf2, gpu=False, autocontrast=True, upscale=1.0, sharpen=True)
        blocks_all += b2

    if pass3:
        b3, (sx3, sy3) = _ocr_pass(img, conf3, gpu=False, autocontrast=True, upscale=upscale, sharpen=True)
        for bb in b3:
            try:
                x0, y0, x1, y1 = map(float, bb.get("bbox") or [0, 0, 0, 0])
                bb["bbox"] = _scale_bbox([x0, y0, x1, y1], sx3, sy3)
            except Exception:
                pass
        blocks_all += b3

    blocks = _dedup_blocks(blocks_all)
    if not blocks:
        return image_bytes, 0

    if ocr_debug:
        for b in blocks:
            log.info("[HWPX][OCR][DBG] img=%s conf=%.3f text=%r bbox=%s",
                filename, float(b.get("conf") or 0.0), str(b.get("text") or ""), b.get("bbox"))

    lines = _group_lines(blocks, y_tol=line_y_tol)

    synthetic: List[Dict[str, Any]] = []
    for line in lines:
        synthetic += _merge_email_from_line_tokens(line, comp)
    synthetic += _merge_cards_from_digit_groups(lines, comp, y_next_tol=card_nextline_tol)

    for s in synthetic:
        s["conf"] = 0.0
        blocks.append(s)

    llm_blocks = blocks
    if ocr_use_llm:
        try:
            llm_blocks = classify_blocks_with_qwen(blocks)
        except Exception:
            llm_blocks = blocks

    KIND_TO_RULES = {
        "email": ["email"],
        "phone": ["phone_mobile", "phone_city"],
        "card": ["card"],
        "id": ["rrn", "fgn", "passport", "driver_license"],
    }

    matched_targets: List[dict] = []

    for b in llm_blocks:
        txt = str(b.get("normalized") or b.get("text") or "").strip()
        if not txt:
            continue

        llm_kind = (b.get("kind") or "none").strip().lower()
        candidates = KIND_TO_RULES.get(llm_kind)

        rule, val = _match_text_to_rules(txt, comp, candidates=candidates) if candidates else (None, None)
        if rule is None:
            rule, val = _match_text_to_rules(txt, comp, candidates=None)

        if rule is None:
            continue

        bb = dict(b)
        bb["kind"] = rule
        bb["normalized"] = val
        matched_targets.append(bb)

    if not matched_targets:
        return image_bytes, 0

    draw = ImageDraw.Draw(img)
    fill_rgba = _image_fill_rgba(ocr_fill)

    hit = 0
    for b in matched_targets:
        try:
            x0, y0, x1, y1 = b.get("bbox", [0, 0, 0, 0])
            x0 = float(x0); y0 = float(y0); x1 = float(x1); y1 = float(y1)
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

        log.info(
            "[HWPX][OCR] img=%s kind=%s text=%r bbox=%s",
            filename,
            b.get("kind") or "none",
            str(b.get("normalized") or b.get("text") or ""),
            (x0, y0, x1, y1),
        )

    if hit <= 0:
        return image_bytes, 0

    out = io.BytesIO()
    try:
        if fmt in ("JPG", "JPEG"):
            img.save(out, format="JPEG", quality=95, optimize=True)
        elif fmt == "BMP":
            img.save(out, format="BMP")
        else:
            img.save(out, format="PNG")
    except Exception:
        return image_bytes, 0

    return out.getvalue(), hit


def hwpx_text(zipf: zipfile.ZipFile) -> str:
    # HWPX zip 내부 텍스트(본문/차트/임베디드) 수집
    out: List[str] = []
    names = zipf.namelist()

    for name in sorted(n for n in names if n.lower().startswith("contents/") and n.endswith(".xml")):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
            out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
        except Exception:
            pass

    for name in sorted(n for n in names if (n.lower().startswith("chart/") or n.lower().startswith("charts/")) and n.endswith(".xml")):
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
    # /text/extract용 텍스트 정리
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
    # 룰 기반 민감정보 추출(scan)
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


def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    # HWPX zip entry 단위 레닥션
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

    ocr_on = _env_bool("HWPX_OCR_IMAGES", True)

    if low.startswith("images/") or low.startswith("image/"):
        if low.endswith(IMAGE_EXTS):
            log.info("[HWPX][IMG] image=%s size=%d", filename, len(data))
            if ocr_on:
                red, hit = _redact_image_bytes(data, comp, filename=filename)
                if hit > 0:
                    log.info("[HWPX][IMG][OCR] redacted=%s hits=%d", filename, hit)
                    return red
        return data

    if low.startswith("bindata/"):
        log.info("[HWPX][BIN] bindata entry=%s size=%d", filename, len(data))

        if low.endswith(IMAGE_EXTS):
            log.info("[HWPX][IMG] bindata image=%s size=%d", filename, len(data))
            if ocr_on:
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
    # 디버그/분석용 이미지 추출
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
