import io
import re
import olefile
import struct
from server.core.redaction_rules import apply_redaction_rules

ASCII_PRINT = (0x0020, 0x007E)       # space ~ '~'
HANGUL_SYLL = (0xAC00, 0xD7A3)       # 가..힣
HANGUL_COMP = (0x3130, 0x318F)       # ㄱ..ㅎ, ㅏ..ㅣ
HANGUL_JAMO = (0x1100, 0x11FF)       # 자모
WHITES      = {0x0009, 0x000A, 0x000D}  # \t \n \r

def _is_allowed_cp(cp: int) -> bool:
    if cp in WHITES: return True
    if ASCII_PRINT[0] <= cp <= ASCII_PRINT[1]: return True
    if HANGUL_SYLL[0] <= cp <= HANGUL_SYLL[1]: return True
    if HANGUL_COMP[0] <= cp <= HANGUL_COMP[1]: return True
    if HANGUL_JAMO[0] <= cp <= HANGUL_JAMO[1]: return True
    return False 


ONLY_PUNCT = re.compile(r"^[\s_\-–—=,.+:/\\|(){}\[\]<>~`!@#$%^&*]+$")

RE_STRUCTURAL = [
    re.compile(r"^_+ppt\d+$", re.I),
    re.compile(r"^text\s*box\s*\d+$", re.I),
    re.compile(r"^(title|subtitle|slide|shape|object|group|table)\s*\d*$", re.I),
]

def _collapse(s: str) -> str:
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r" ?\n ?", "\n", s)
    return s.strip()

def _is_ascii_small_word(s: str) -> bool:
    if len(s) <= 6 and re.fullmatch(r"[A-Za-z]{2,6}", s):
        return True
    return False

def _is_structural_name(s: str) -> bool:
    for rx in RE_STRUCTURAL:
        if rx.match(s):
            return True
    return False

def _has_meaning_chars(s: str) -> bool:
    return bool(re.search(r"[가-힣A-Za-z0-9]", s))

def _is_garbage_line(s: str) -> bool:
    if len(s) < 2: return True
    if ONLY_PUNCT.match(s): return True
    total = len(s)
    h = sum(1 for ch in s if "가" <= ch <= "힣")
    a = sum(1 for ch in s if ch.isalpha())
    d = sum(1 for ch in s if ch.isdigit())
    if (h + a + d) / max(total, 1) < 0.3:
        return True
    return False


def _utf16_runs_from(buf: bytes, start_offset: int) -> list[str]:
    out, run = [], []
    i, n = start_offset, len(buf)

    def flush():
        nonlocal run
        if not run: return
        s = _collapse("".join(run))
        run = []
        if s:
            out.append(s)

    while i + 1 < n:
        cp = buf[i] | (buf[i + 1] << 8)
        if _is_allowed_cp(cp):
            if cp in (0x000A, 0x000D): run.append("\n")
            elif cp == 0x0009:         run.append("\t")
            else:                      run.append(chr(cp))
        else:
            flush()
        i += 2
    flush()
    return out


def extract_text(file_bytes: bytes) -> dict:
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("PowerPoint Document"):
            raise ValueError("PowerPoint Document 스트림이 없습니다.")
        buf = ole.openstream("PowerPoint Document").read()

    candidates = _utf16_runs_from(buf, 0) + _utf16_runs_from(buf, 1)

    freq = {}
    for s in candidates:
        freq[s] = freq.get(s, 0) + 1

    filtered = []
    seen = set()
    for s in candidates:
        if s in seen:  
            continue
        seen.add(s)

        if not _has_meaning_chars(s):
            continue
        if _is_garbage_line(s):
            continue
        if _is_structural_name(s):
            continue
        if _is_ascii_small_word(s):
            continue
        if freq.get(s, 0) >= 3:
            continue

        filtered.append(s)

    full_text = "\n".join(filtered)
    return {"full_text": full_text, "pages": [{"page": 1, "text": full_text}]}

def redact(file_bytes: bytes) -> bytes:
    """PPT 포맷 유지형: TextCharsAtom 교체"""
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("PowerPoint Document"):
            return file_bytes
        buf = bytearray(ole.openstream("PowerPoint Document").read())

    off = 0
    while off + 8 < len(buf):
        try:
            recVer, recInstance, recType, recLen = struct.unpack_from("<HHII", buf, off)
        except struct.error:
            break
        off += 8

        if recType == 0x0FA0:  # TextCharsAtom
            raw = buf[off:off + recLen]
            try:
                text = raw.decode("utf-16le", errors="ignore")
                red = apply_redaction_rules(text)
                enc = red.encode("utf-16le")
                buf[off:off + recLen] = enc[:recLen].ljust(recLen, b"\x00")
            except Exception:
                pass
        off += recLen

    return bytes(buf)