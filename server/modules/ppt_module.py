from io import BytesIO
import struct
import re
from typing import List, Tuple, Iterable, Optional, Any, TYPE_CHECKING
import unicodedata

import unicodedata

_ZW_CHARS = r"\u200B\u200C\u200D\uFEFF"
def _norm_line(t: str) -> str:
    t = unicodedata.normalize("NFKC", t or "")
    t = re.sub(f"[{_ZW_CHARS}]", "", t)
    t = re.sub(r"[\s\u00A0\u202F\u3000]+", " ", t).strip()
    return t

_RE_MASTER_LEVEL = re.compile(
    r"^(?:[•·\*\-\–\—◦●○◆◇▪▫▶▷■□·]+\s*)?"
    r"(?:첫|둘|셋|넷|다섯|여섯|일곱|여덟|아홉|열|[0-9]+)\s*(?:번째)?\s*수준\s*$",
    re.IGNORECASE
)


# 외부 의존
try:
    import olefile  
except Exception:
    olefile = None  

if TYPE_CHECKING:
    from olefile import OleFileIO as _OleFileIO
    OleFileIO = _OleFileIO 
else:
    OleFileIO = Any

# 규칙/검증기 로더(옵션)
_RULES: Optional[dict] = None
_VALIDATORS: Optional[dict] = None

def _try_load_rules_and_validators() -> None:
    global _RULES, _VALIDATORS
    for mod, name in [
        ("server.modules.redaction_rules", "RULES"),
        ("server.core.redaction_rules", "RULES"),
        ("redaction_rules", "RULES"),
    ]:
        try:
            m = __import__(mod, fromlist=[name]) 
            _RULES = getattr(m, name, None) or _RULES
        except Exception:
            pass
    for mod in ["server.modules.validators","server.core.validators","validators"]:
        try:
            m = __import__(mod, fromlist=["*"])  
            _VALIDATORS = _VALIDATORS or {}
            for key in (
                "is_valid_rrn","is_valid_fgn","is_valid_phone_mobile","is_valid_phone_city",
                "is_valid_email","is_valid_card","is_valid_driver_license",
            ):
                fn = getattr(m, key, None)
                if callable(fn):
                    _VALIDATORS[key.replace("is_valid_","")] = fn
        except Exception:
            pass

_try_load_rules_and_validators()


PPT_EXTRACT_EMBEDDED = False
PPT_CLEANUP_STRICT = False

_HDR = struct.Struct("<HHI")
_TEXTCHARSATOM = 0x0FA0  
_TEXTBYTESATOM = 0x0FA8 

_LINE_NOISE = re.compile(
    r"마스터\s*(?:제목|텍스트)\s*스타일.*"
    r"|클릭하여\s*(?:제목|텍스트)(?:\s*스타일을)?\s*편집하려면\s*클릭"
    r"|클릭하여\s*(?:제목|텍스트)\s*입력"
    r"|제목(?:을)?\s*입력"
    r"|부제목(?:을)?\s*입력"
    r"|(?:첫|둘|셋|넷|다섯|여섯|일곱|여덟|아홉|열|[0-9]+)\s*(?:번째)?\s*수준"
    r"^(?:"
    r"Office\s*테마|TextBox\s*\d+|___PPT\d+|Excel\.Chart\.\d+|Microsoft\s*Excel\s*차트"
    r"|맑은\s*고딕|Arial"
    r")\b"
)

def _cleanup(s: str) -> str:
    out = []
    for raw in (s or "").replace("\r", "\n").split("\n"):
        if not raw.strip():
            continue

        n = _norm_line(raw)
        if not n:
            continue

        # ‘수준’ 플레이스홀더 컷 (두/세/네/다섯/숫자 모든 변종 대응)
        if _RE_MASTER_LEVEL.match(n):
            continue

        # 기존 노이즈(마스터 문구/차트·폰트 등)
        if _LINE_NOISE.search(n):
            continue

        # 불릿만 있는 줄 컷
        if re.fullmatch(r"[\s•·\*\-\–\—◦●○◆◇▪▫▶▷■□·]+", n):
            continue

        # 가독성 휴리스틱(과하면 낮추세요)
        letters = sum(ch.isalnum() or ch.isspace() for ch in n)
        if letters / max(1, len(n)) < 0.2:
            continue

        out.append(n)
    return "\n".join(out)


def _walk_records(buf: bytes, base_off: int = 0) -> Iterable[Tuple[int,int,int,int]]:
    # 재귀적으로 컨테이너( recVer == 0xF ) 내부까지 순회
    i, n = 0, len(buf)
    while i + _HDR.size <= n:
        verInst, rtype, rlen = _HDR.unpack_from(buf, i)
        rec_ver = verInst & 0x000F
        i_hdr_end = i + _HDR.size
        i_data_end = i_hdr_end + rlen
        if i_data_end > n:
            break
        data_off_abs = base_off + i_hdr_end
        if rec_ver == 0xF:
            child = buf[i_hdr_end:i_data_end]
            yield from _walk_records(child, base_off + i_hdr_end)
        else:
            yield (rec_ver, rtype, rlen, data_off_abs)
        i = i_data_end


def _read_powerpoint_document(ole: OleFileIO) -> bytes:
    with ole.openstream("PowerPoint Document") as fp:  # type: ignore[attr-defined]
        return fp.read()


def _extract_text_from_records(doc_bytes: bytes) -> str:
    chunks: List[str] = []
    for _rec_ver, rtype, rlen, data_off in _walk_records(doc_bytes):
        if rlen <= 0:
            continue
        try:
            if rtype == _TEXTCHARSATOM:
                b = doc_bytes[data_off : data_off + rlen]
                chunks.append(b.decode("utf-16le", errors="ignore"))
            elif rtype == _TEXTBYTESATOM:
                b = doc_bytes[data_off : data_off + rlen]
                for enc in ("cp949","cp1252","latin1"):
                    try:
                        chunks.append(b.decode(enc))
                        break
                    except Exception:
                        continue
        except Exception:
            continue
    return _cleanup("\n".join(chunks))


def _extract_embedded_noise_prone(ole: OleFileIO) -> str:
    out = []
    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        if not any(key in path for key in ("embeddings", "ObjectPool", "Ole10Native", "Package")):
            continue
        try:
            with ole.openstream(entry) as fp:
                blob = fp.read()
            for enc in ("utf-16le", "utf-8", "cp949", "latin1"):
                try:
                    out.append(blob.decode(enc))
                    break
                except Exception:
                    continue
        except Exception:
            continue
    return _cleanup("\n".join(out))


# 규칙 기반 시크릿 탐지(동일 길이 마스킹용)
def _iter_rule_matches(text: str):
    if not _RULES:
        return []
    spans: List[Tuple[int, int]] = []
    for _key, spec in _RULES.items():
        rx = spec.get("regex")
        if not rx:
            continue
        validator = None
        if _VALIDATORS and spec.get("validator_name"):
            validator = _VALIDATORS.get(spec["validator_name"])
        elif callable(spec.get("validator")):
            validator = spec["validator"]
        for m in re.finditer(rx, text):
            ok = True
            if validator:
                try:
                    ok = bool(validator(m.group(0)))
                except Exception:
                    ok = True
            if ok:
                spans.append((m.start(), m.end()))
    spans.sort()
    merged: List[Tuple[int, int]] = []
    for s, e in spans:
        if not merged or s > merged[-1][1]:
            merged.append((s, e))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    return merged


def _mask_same_len(text: str, spans):
    if not spans:
        return text
    out = []
    cur = 0
    for s, e in spans:
        if s > cur:
            out.append(text[cur:s])
        out.append("*" * (e - s))
        cur = e
    if cur < len(text):
        out.append(text[cur:])
    return "".join(out)


# 공개 API
def extract_text(file_bytes: bytes):
    if olefile is None:
        raise RuntimeError("olefile 모듈이 필요합니다. pip install olefile")
    with olefile.OleFileIO(BytesIO(file_bytes)) as ole:
        doc = _read_powerpoint_document(ole)
        text_main = _extract_text_from_records(doc)
        if PPT_EXTRACT_EMBEDDED:
            text_emb = _extract_embedded_noise_prone(ole)
            if text_emb:
                text_main = _cleanup(text_main + "\n" + text_emb)

    pages = [{"index": 1, "text": text_main or ""}]
    return {"full_text": text_main or "", "pages": pages}

def redact(file_bytes: bytes) -> bytes:
    try:
        from .ole_redactor import redact_ole_bin_preserve_size  
    except Exception:
        try:
            from ole_redactor import redact_ole_bin_preserve_size 
        except Exception:
            redact_ole_bin_preserve_size = None 

    if redact_ole_bin_preserve_size is None: 
        return file_bytes

    try:
        text = (extract_text(file_bytes) or {}).get("full_text","")
    except Exception:
        return file_bytes

    secrets: List[str] = []
    if text:
        spans = list(_iter_rule_matches(text)) if _RULES else []
        if spans:
            _ = _mask_same_len(text, spans)
            for s, e in spans:
                seg = text[s:e].strip()
                if len(seg) >= 2:
                    secrets.append(seg)
        if secrets:
            uniq, seen = [], set()
            for s in secrets:
                if s not in seen:
                    seen.add(s); uniq.append(s)
            secrets = uniq

    if not secrets:
        return file_bytes

    try:
        return redact_ole_bin_preserve_size(file_bytes, secrets, mask_preview=False)
    except Exception:
        return file_bytes
