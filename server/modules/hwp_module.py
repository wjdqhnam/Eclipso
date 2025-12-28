from __future__ import annotations

import io
import zlib
import struct
import re
from typing import List, Tuple, Optional, Dict, Any
import olefile

from server.core.normalize import normalization_text
from server.core.matching import find_sensitive_spans
from server.modules.ocr_image_redactor import redact_image_bytes


# ─────────────────────────────
# HWP / CTRL TAG 상수
# ─────────────────────────────
TAG_PARA_TEXT = 67
TAG_PICTURE = 0x04F
HWPTAG_CTRL_HEADER = 0x0010
HWPTAG_CTRL_DATA   = 0x0011
ENDOFCHAIN = 0xFFFFFFFE

def MAKE_4CHID(a, b, c, d) -> int:
    return (a | (b << 8) | (c << 16) | (d << 24))

CTRLID_OLE = MAKE_4CHID(ord('$'), ord('o'), ord('l'), ord('e'))


# ─────────────────────────────
# 압축 관련 유틸리티
# ─────────────────────────────
# HWP 섹션 압축 해제
def _decompress(raw: bytes) -> Tuple[bytes, int]:
    for w in (-15, +15):
        try:
            return zlib.decompress(raw, w), w
        except zlib.error:
            pass
    return raw, 0


# HWP 섹션 재압축
def _recompress(buf: bytes, mode: int) -> bytes:
    if mode == 0:
        return buf
    c = zlib.compressobj(level=9, wbits=mode)
    return c.compress(buf) + c.flush()

def decomp_bin(raw: bytes, off: int, kind: str):
    data = raw[off:]
    try:
        if kind == "zlib":
            obj = zlib.decompressobj()
            dec = obj.decompress(data)
            consumed = len(data) - len(obj.unused_data)
        elif kind == "gzip":
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            dec = obj.decompress(data)
            consumed = len(data) - len(obj.unused_data)
        else:
            obj = zlib.decompressobj(-15)
            dec = obj.decompress(data)
            consumed = len(data) - len(obj.unused_data)
        if consumed <= 0 or len(dec) == 0:
            return None
        return dec, consumed
    except Exception:
        return None

def recomp_bin(kind: str, dec: bytes) -> Optional[bytes]:
    if kind == "zlib":
        return zlib.compress(dec)
    if kind == "rawdef":
        co = zlib.compressobj(level=6, wbits=-15)
        return co.compress(dec) + co.flush()
    if kind == "gzip":
        co = zlib.compressobj(
            level=6,
            wbits=16 + zlib.MAX_WBITS
        )
        return co.compress(dec) + co.flush()
    return None


# ─────────────────────────────
# OLE 내부 구조 유틸리티
# ─────────────────────────────
# OLE direntry 조회
def _direntry_for(ole: olefile.OleFileIO, path: Tuple[str, ...]):
    try:
        r = ole._find(path)
        if isinstance(r, int):
            return ole.direntries[r]
        return r
    except Exception:
        return None


# MiniStream 섹터 오프셋 수집
def _collect_ministream_offsets(ole: olefile.OleFileIO) -> List[int]:
    root = getattr(ole, "root", None)
    if root is None:
        return []

    sec = ole.sector_size
    fat = ole.fat
    s = root.isectStart

    out: List[int] = []
    while s not in (-1, olefile.ENDOFCHAIN) and 0 <= s < len(fat):
        out.append((s + 1) * sec)
        s = fat[s]
    return out


# BigFAT 체인 덮어쓰기
def _overwrite_bigfat(ole, container: bytearray, start: int, new_raw: bytes) -> int:
    sec = ole.sector_size
    fat = ole.fat
    s = start
    pos = 0

    while s not in (-1, olefile.ENDOFCHAIN) and pos < len(new_raw):
        off = (s + 1) * sec
        chunk = new_raw[pos:pos + sec]
        container[off:off + len(chunk)] = chunk
        pos += len(chunk)
        s = fat[s]

    return pos


# MiniFAT 체인 덮어쓰기
def _overwrite_minifat_chain(ole, container: bytearray, start: int, new_raw: bytes) -> int:
    ole.loadminifat()
    mini = ole.mini_sector_size
    minifat = ole.minifat
    offs = _collect_ministream_offsets(ole)

    pos = 0
    s = start
    while s not in (-1, olefile.ENDOFCHAIN) and pos < len(new_raw):
        moff = s * mini
        bi = moff // ole.sector_size
        if bi >= len(offs):
            break

        file_off = offs[bi] + (moff % ole.sector_size)
        chunk = new_raw[pos:pos + mini]
        container[file_off:file_off + len(chunk)] = chunk

        pos += len(chunk)
        s = minifat[s]

    return pos


# ─────────────────────────────
# HWP 레코드 파서 / Ctrl 파싱
# ─────────────────────────────
# HWP 레코드 단위 파서
def iter_hwp_records(section_bytes: bytes):
    off = 0
    n = len(section_bytes)

    while off + 4 <= n:
        hdr = int.from_bytes(section_bytes[off:off + 4], "little")
        tag = hdr & 0x3FF
        level = (hdr >> 10) & 0x3FF
        size = (hdr >> 20) & 0xFFF

        rec_start = off
        off += 4

        if size == 0xFFF:
            if off + 4 > n:
                break
            size = int.from_bytes(section_bytes[off:off + 4], "little")
            off += 4

        if off + size > n:
            yield tag, level, section_bytes[off:n], rec_start, n
            break

        yield tag, level, section_bytes[off:off + size], rec_start, off + size
        off += size

# CtrlHeader 파싱
def parse_ctrl_header(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[:4], "little")


# CtrlData에서 BinDataID 추출
def parse_bindata_id_from_ctrldata(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[:4], "little")


# $ole 컨트롤 기반 BinDataID 탐색
def discover_ole_ids(section_bytes: bytes) -> List[int]:
    ids: List[int] = []
    pending: Optional[int] = None

    for tag, level, payload, _, _ in iter_hwp_records(section_bytes):
        if tag == HWPTAG_CTRL_HEADER:
            pending = level if parse_ctrl_header(payload) == CTRLID_OLE else None
        elif pending is not None:
            if tag == HWPTAG_CTRL_DATA and level == pending:
                bid = parse_bindata_id_from_ctrldata(payload)
                if bid is not None:
                    ids.append(bid)
                pending = None
            elif level < pending:
                pending = None

    return ids


# HWP 본문 텍스트에 섞여 나오는 제어문자/쓰레기 유니코드 제거(줄바꿈/탭은 유지)
_CTRL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_SPACE_RUN = re.compile(r"[ \u00A0\u2007\u202F]{2,}")
_TRAIL_SPACE = re.compile(r"[ \t]+$")

def _is_allowed_hwp_char(ch: str) -> bool:
    """
    HWP TAG_PARA_TEXT는 텍스트 외 데이터가 섞여 나오는 경우가 있어,
    한글/영문/숫자/일반 구두점/이메일 기호 중심으로 화이트리스트 적용.
    """
    if not ch:
        return False
    o = ord(ch)
    if ch in ("\n", "\t", " "):
        return True
    # ASCII printable
    if 0x21 <= o <= 0x7E:
        return True
    # Hangul syllables + jamo (한글)
    if 0xAC00 <= o <= 0xD7A3:
        return True
    if 0x1100 <= o <= 0x11FF:
        return True
    if 0x3130 <= o <= 0x318F:
        return True
    # (선택) 원화기호/중점 등 문서에서 흔한 기호
    if o in (0x20A9, 0x00B7):
        return True
    return False

def _clean_hwp_text(s: str) -> str:
    if not s:
        return ""

    # CR은 LF로 통일
    s = s.replace("\r", "\n")

    # 1) 제어문자 제거 (LF/TAB은 유지)
    s = _CTRL_CHARS.sub("", s)

    # 2) 허용 문자만 보존, 나머지는 공백으로 치환(이메일 같은 경우 단어가 붙는 걸 방지)
    out_chars: List[str] = []
    for ch in s:
        out_chars.append(ch if _is_allowed_hwp_char(ch) else " ")
    s2 = "".join(out_chars)

    # 3) 공백 정리 (줄 단위 trailing 제거 + 연속 공백 축약)
    lines: List[str] = []
    for raw in s2.split("\n"):
        raw = _SPACE_RUN.sub(" ", raw)
        raw = _TRAIL_SPACE.sub("", raw)
        # 쓰레기만 남은 라인 제거(문자/숫자/한글/@ 없는 경우 드랍)
        stripped = raw.strip()
        if not stripped:
            lines.append("")
            continue
        has_signal = any(
            ("0" <= c <= "9") or ("A" <= c <= "Z") or ("a" <= c <= "z") or (c == "@") or ("\uAC00" <= c <= "\uD7A3")
            for c in stripped
        )
        if not has_signal:
            lines.append("")
            continue
        lines.append(stripped)

    # 연속 빈 줄 축약(최대 1줄)
    cleaned_lines: List[str] = []
    prev_blank = False
    for ln in lines:
        is_blank = (ln.strip() == "")
        if is_blank and prev_blank:
            continue
        cleaned_lines.append(ln)
        prev_blank = is_blank

    return "\n".join(cleaned_lines).strip()


# ─────────────────────────────
# 이미지 추출
# ─────────────────────────────
IMAGE_EXTS = (".bmp", ".gif", ".jpg", ".jpeg",".pcx", ".pic", ".png", ".tif", ".tiff")

def is_image_exts(name: str) -> bool:
    return name.lower().endswith(IMAGE_EXTS)

# BinData에서 이미지 스트림 추출
def extract_bindata_images(file_bytes: bytes) -> list[dict]:
    results = []

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        for path in ole.listdir(streams=True, storages=False):
            # BinData/<stream>
            if len(path) != 2 or path[0] != "BinData":
                continue

            name = path[1]
            lower = name.lower()

            if not lower.endswith(IMAGE_EXTS):
                continue

            try:
                raw = ole.openstream(path).read()
            except Exception:
                continue

            results.append({
                "stream_path": tuple(path),
                "filename": name,
                "ext": lower[lower.rfind("."):],
                "bytes": raw,
            })

    return results


# 이미지 ocr 레닥션 처리 후 교체
def replace_img(img_bytes: bytes, meta: dict) -> bytes:
    try:
        redacted, hit = redact_image_bytes(
            img_bytes,
            filename=meta.get("filename", "image"),
            env_prefix="HWP",
        )
    except Exception:
        return img_bytes  # OCR 실패시 원본 유지

    # OCR 결과 없다면 원본 유지
    if not hit:
        return img_bytes

    if len(redacted) < len(img_bytes):
        return redacted + b"\x00" * (len(img_bytes) - len(redacted))

    if len(redacted) > len(img_bytes):
        return img_bytes  # 커지면 원본 유지

    return redacted



# ─────────────────────────────
# 문자 추출
# ─────────────────────────────
# BodyText에서 전체 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
    texts: List[str] = []

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        for path in ole.listdir(streams=True, storages=False):
            if len(path) < 2 or path[0] != "BodyText" or not path[1].startswith("Section"):
                continue

            dec, _ = _decompress(ole.openstream(path).read())
            for tag, _, payload, _, _ in iter_hwp_records(dec):
                if tag == TAG_PARA_TEXT:
                    texts.append(_clean_hwp_text(payload.decode("utf-16le", "ignore")))

    # TAG_PARA_TEXT는 문단 단위 텍스트 조각이므로, 문단 경계를 '\n'으로 보존한다.
    # (그대로 이어붙이면 NER 입력에서 레이아웃/문맥이 사라져 탐지 품질이 떨어질 수 있음)
    full = "\n".join(t for t in texts if t is not None)
    return {"full_text": full, "pages": [{"page": 1, "text": full}]}


# 본문 기준 민감 문자열 수집
def _collect_targets_by_regex(text: str) -> List[str]:
    targets: List[str] = []
    for _, _, val, _ in find_sensitive_spans(text):
        if val and val.strip():
            targets.append(val)
    return sorted(set(targets), key=lambda x: (-len(x), x))


# ─────────────────────────────
# 바이트 치환 유틸
# ─────────────────────────────
# 하이픈 제외 마스킹 헬퍼 유틸
def _except_hyphen(text: str) -> str:
    return "".join(ch if ch in "-@" else "*" for ch in text)

# 특정 인코딩 기준 동일 길이 마스킹
def replace_bytes_with_enc(data: bytes, old: str, enc: str, max_log: int = 0):
    try:
        needle = old.encode(enc, "ignore")
    except Exception:
        return data, 0, []

    if not needle:
        return data, 0, []

    masked_text = _except_hyphen(old)

    if enc == "utf-16le":
        repl = masked_text.encode("utf-16le")
    else:
        repl = masked_text.encode(enc, errors="ignore")

    if len(repl) != len(needle):
        return data, 0, []

    ba = bytearray(data)
    i = cnt = 0

    while True:
        j = ba.find(needle, i)
        if j == -1:
            break
        ba[j:j + len(needle)] = repl
        cnt += 1
        i = j + len(needle)

    return bytes(ba), cnt, []


# 여러 인코딩으로 치환 시도
def try_patterns(blob: bytes, text: str, max_log: int = 0):
    total = 0
    cur = blob

    for enc in ("utf-16le", "utf-8", "cp949"):
        cur, cnt, _ = replace_bytes_with_enc(cur, text, enc, max_log)
        total += cnt

    return cur, total, []


# ─────────────────────────────
# BinData - OLE 처리
# ─────────────────────────────
CFB = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
PNG = b"\x89PNG\r\n\x1a\n"
GZ  = b"\x1F\x8B"
JPG = b"\xFF\xD8\xFF"
WMF = b"\xD7\xCD\xC6\x9A"


# BinData에서 텍스트 기반 타겟 추출
def _collect_targets_from_blob_text(blob: bytes) -> List[str]:
    targets: List[str] = []

    for enc in ("utf-16le", "utf-8", "cp949"):
        try:
            text = blob.decode(enc, "ignore")
        except Exception:
            continue

        norm = normalization_text(text)
        for _, _, val, _ in find_sensitive_spans(norm):
            if val and val.strip():
                targets.append(val)

    return sorted(set(targets), key=lambda x: (-len(x), x))


def magic_hits(raw: bytes):
    hits = []
    if raw.startswith(CFB): hits.append(("ole", 0))
    if raw.startswith(PNG): hits.append(("png", 0))
    if raw.startswith(GZ):  hits.append(("gzip", 0))
    if raw.startswith(JPG): hits.append(("jpeg", 0))
    if raw.startswith(WMF): hits.append(("wmf", 0))
    for sig, name in [(CFB, "ole"), (PNG, "png"), (GZ, "gzip")]:
        off = raw.find(sig, 1)
        if off != -1:
            hits.append((name, off))
    return hits


def is_zlib_head(b: bytes) -> bool:
    return len(b) >= 2 and b[0] == 0x78 and b[1] in (0x01, 0x9C, 0xDA)


# raw 내부에서 zlib 헤더/ gzip 헤더/ rawdef 후보를 만들어서 (kind, offset) 목록 반환
def scan_deflate(raw: bytes, limit: int = 64, step: int = 64):
    cand = []
    n = len(raw)
    for i in range(n - 1):
        if is_zlib_head(raw[i:i + 2]):
            cand.append(("zlib", i))
        if raw[i:i + 2] == GZ:
            cand.append(("gzip", i))
    for i in range(0, n, step):
        cand.append(("rawdef", i))

    out = []
    seen = set()
    for k, o in cand:
        if (k, o) in seen:
            continue
        seen.add((k, o))
        out.append((k, o))
        if len(out) >= limit:
            break
    return out

# 기존 바이너리 안에 부분 덮어쓰기
def patch_seg(raw: bytes, off: int, consumed: int, new_comp: bytes) -> Optional[bytes]:
    seg = raw[off: off + consumed]
    if len(new_comp) > len(seg):
        return None
    if len(new_comp) < len(seg):
        new_comp = new_comp + b"\x00" * (len(seg) - len(new_comp))
    return raw[:off] + new_comp + raw[off + len(seg):]


def _replace_in_bindata_smart(raw: bytes) -> Tuple[bytes, int]:
    total_hits = 0
    out = raw

    # raw 자체에서 targets 뽑고 직접 치환
    raw_targets = _collect_targets_from_blob_text(out)
    if raw_targets:
        for t in raw_targets:
            out2, hits, _ = try_patterns(out, t, max_log=0)
            if hits:
                out = out2
                total_hits += hits

    # 압축 해제된 ole파일에서 targets 뽑고 치환 후 재압축+패치
    cands = scan_deflate(out, limit=32, step=128)

    for kind, off in cands:
        decinfo = decomp_bin(out, off, kind)
        if not decinfo:
            continue

        dec, consumed = decinfo

        # 압축 해제된 ole파일에서 다시 targets 산출
        dec_targets = _collect_targets_from_blob_text(dec)

        changed = dec
        seg_hits = 0
        for t in dec_targets:
            changed2, hits, _ = try_patterns(changed, t, max_log=0)
            if hits:
                seg_hits += hits
                changed = changed2

        if seg_hits <= 0:
            continue

        comp = recomp_bin(kind, changed)
        if comp is None:
            continue

        patched = patch_seg(out, off, consumed, comp)
        if patched is None:
            continue

        out = patched
        total_hits += seg_hits

    # 길이 불변 방어
    if len(out) != len(raw):
        return raw, 0

    return out, total_hits


# ─────────────────────────────
# 레닥션 메인
# ─────────────────────────────
def redact(file_bytes: bytes, spans: Optional[List[Dict[str, Any]]] = None) -> bytes:
    container = bytearray(file_bytes)

    full_raw = extract_text(file_bytes)["full_text"]
    full_norm = normalization_text(full_raw)
    targets = _collect_targets_by_regex(full_norm)

    # NER spans에서 텍스트 추출하여 targets에 추가
    if spans:
        for span in spans:
            if not isinstance(span, dict):
                continue
            s = span.get("start")
            e = span.get("end")
            if s is None or e is None:
                continue
            try:
                s = int(s)
                e = int(e)
            except Exception:
                continue
            if e <= s or s < 0 or e > len(full_raw):
                continue
            target_text = full_raw[s:e]
            if target_text and target_text.strip():
                targets.append(target_text)
    
    # 중복 제거 및 정렬
    targets = sorted(set(targets), key=lambda x: (-len(x), x))

    print(f"[DBG] sensitive targets = {targets}")

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        streams = ole.listdir(streams=True, storages=False)
        cutoff = getattr(ole, "minisector_cutoff", 4096)

        # ─────────────────────────────
        # BodyText 레닥션 (문단 텍스트)
        # ─────────────────────────────
        for path in streams:
            if not (len(path) >= 2 and path[0] == "BodyText" and path[1].startswith("Section")):
                continue
            raw = ole.openstream(path).read()
            dec, mode = _decompress(raw)
            buf = bytearray(dec)

            off, n = 0, len(buf)
            while off + 4 <= n:
                hdr = struct.unpack_from("<I", buf, off)[0]
                tag = hdr & 0x3FF
                size = (hdr >> 20) & 0xFFF
                off += 4
                if size < 0 or off + size > n:
                    break
                if tag == TAG_PARA_TEXT and size > 0:
                    seg = bytes(buf[off:off + size])
                    for t in targets:
                        seg, _, _ = replace_bytes_with_enc(seg, t, "utf-16le")
                    buf[off:off + size] = seg
                off += size

            new_raw = _recompress(bytes(buf), mode)
            if len(new_raw) < len(raw):
                new_raw = new_raw + b"\x00" * (len(raw) - len(new_raw))
            elif len(new_raw) > len(raw):
                new_raw = new_raw[:len(raw)]

            entry = _direntry_for(ole, tuple(path))
            if entry:
                if entry.size < cutoff:
                    _overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
                else:
                    _overwrite_bigfat(ole, container, entry.isectStart, new_raw)

        # ─────────────────────────────
        # BinData 처리
        # ─────────────────────────────
        for path in streams:
            if len(path) != 2 or path[0] != "BinData":
                continue

            name = path[1]

            try:
                raw = ole.openstream(path).read()
            except Exception as e:
                print(f"[DBG][BinData] read failed: {e}")
                continue

            entry = _direntry_for(ole, path)
            if not entry:
                continue

            # 이미지 -> OCR
            if is_image_exts(name):
                new_raw = replace_img(
                    raw,
                    {"filename": name}
                )

                # OCR 결과가 없거나 변경 없으면 스킵
                if new_raw == raw:
                    continue

            # 차트
            else:
                new_raw, hit = _replace_in_bindata_smart(raw)

                if hit <= 0:
                    continue

                if len(new_raw) != len(raw):
                    continue

            # 덮어쓰기
            if entry.size < cutoff:
                _overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
            else:
                _overwrite_bigfat(ole, container, entry.isectStart, new_raw)


        # ─────────────────────────────
        # Prv 계열 처리
        # ─────────────────────────────
        for path in streams:
            if len(path) == 1:
                name = path[0].lower()

                # PrvText
                if "prv" in name and "text" in name:
                    raw = ole.openstream(path).read()
                    new_raw = raw
                    for t in targets:
                        new_raw, _, _ = replace_bytes_with_enc(new_raw, t, "utf-16le")

                    if len(new_raw) < len(raw):
                        new_raw = new_raw + b"\x00" * (len(raw) - len(new_raw))
                    elif len(new_raw) > len(raw):
                        new_raw = new_raw[:len(raw)]

                    entry = _direntry_for(ole, path)
                    if entry:
                        if entry.size < cutoff:
                            _overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
                        else:
                            _overwrite_bigfat(ole, container, entry.isectStart, new_raw)

                # PrvImage
                if "prv" in name and "image" in name:
                    raw = ole.openstream(path).read()
                    new_raw = b"\x00" * len(raw)

                    entry = _direntry_for(ole, path)
                    if entry:
                        if entry.size < cutoff:
                            _overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
                        else:
                            _overwrite_bigfat(ole, container, entry.isectStart, new_raw)

    return bytes(container)