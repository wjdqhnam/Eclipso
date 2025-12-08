from __future__ import annotations
import io, zlib, struct
from typing import List, Tuple
import olefile

from server.core.normalize import normalization_text
from server.core.matching import find_sensitive_spans  

# ─────────────────────────────
# Tag constants
# ─────────────────────────────
TAG_PARA_TEXT = 67  
TAG_PICTURE   = 0x04F     # 그림 개체 태그


# ─────────────────────────────
# 압축 유틸
# ─────────────────────────────
def _decompress(raw: bytes) -> Tuple[bytes, int]:
    for w in (-15, +15):
        try:
            return zlib.decompress(raw, w), w
        except zlib.error:
            pass
    return raw, 0

def _recompress(buf: bytes, mode: int) -> bytes:
    if mode == 0:
        return buf
    c = zlib.compressobj(level=9, wbits=mode)
    return c.compress(buf) + c.flush()


# ─────────────────────────────
# Magic signatures for images/ole
# ─────────────────────────────
CFB = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"   # OLE Compound
PNG = b"\x89PNG\r\n\x1a\n"
GZ  = b"\x1F\x8B"
JPG = b"\xFF\xD8\xFF"
WMF = b"\xD7\xCD\xC6\x9A"


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

# ─────────────────────────────
# 문자열 교체 유틸
# ─────────────────────────────
def mask_same_len(b: bytes, fill: bytes = b"*") -> bytes:
    if not b: return b
    need = len(b)
    return (fill * ((need + len(fill) - 1) // len(fill)))[:need]

def replace_bytes_with_enc(data: bytes, old_text: str, enc: str):
    needle = old_text.encode(enc)
    mask_char = "*" if enc.lower() == "utf-16le" else "＊"
    repl = (mask_char * len(old_text)).encode(enc)
    if len(repl) != len(needle):
        repl = b"*" * len(needle)
    ba = bytearray(data)
    i = 0; n = len(needle); cnt = 0
    while True:
        j = ba.find(needle, i)
        if j == -1: break
        ba[j:j+n] = repl
        cnt += 1
        i = j + n
    return bytes(ba), cnt

def try_patterns(blob: bytes, text: str):
    total = 0; cur = blob
    for enc in ["utf-16le", "utf-8", "cp949"]:
        try:
            cur2, cnt = replace_bytes_with_enc(cur, text, enc)
        except Exception:
            cnt = 0; cur2 = cur
        if cnt > 0:
            total += cnt
            cur = cur2
    return cur, total


# ─────────────────────────────
# deflate/zlib 탐색기
# ─────────────────────────────
def is_zlib_head(b: bytes):
    return len(b) >= 2 and b[0] == 0x78 and b[1] in (0x01, 0x9C, 0xDA)

def scan_deflate(raw: bytes, limit: int = 64, step: int = 64):
    n = len(raw); cand = []
    for i in range(n - 1):
        if is_zlib_head(raw[i:i + 2]): cand.append(("zlib", i))
        if raw[i:i + 2] == GZ:        cand.append(("gzip", i))
    for i in range(0, n, step):
        cand.append(("rawdef", i))
    out, seen = [], set()
    for k, o in cand:
        if (k, o) in seen: continue
        seen.add((k, o))
        out.append((k, o))
        if len(out) >= limit:
            break
    return out

def decomp_at(raw: bytes, off: int, kind: str):
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

def recompress(kind: str, dec: bytes):
    if kind == "zlib":
        return zlib.compress(dec)
    if kind == "rawdef":
        co = zlib.compressobj(level=6, wbits=-15)
        return co.compress(dec) + co.flush()
    return None

def patch_seg(raw: bytes, off: int, consumed: int, new_comp: bytes):
    seg = raw[off:off + consumed]
    if len(new_comp) > len(seg):
        return None
    if len(new_comp) < len(seg):
        new_comp = new_comp + b"\x00" * (len(seg) - len(new_comp))
    return raw[:off] + new_comp + raw[off + len(seg):]

def process_bindata(raw: bytes, sensitive: str):
    hits = 0
    mags = magic_hits(raw)

    # PNG/JPG/WMF 이미지면 구조 유지하고 그대로 반환
    if any(k in ("png", "jpeg", "wmf") and o == 0 for k, o in mags):
        return raw, 0

    # 내부 OLE 일 경우 내부 스트림에서 레닥션
    for k, o in mags:
        if k == "ole":
            try:
                inner = olefile.OleFileIO(io.BytesIO(raw[o:]))
                names = ["/".join(s) for s in inner.listdir(streams=True, storages=False)]
                cur = raw
                for s in names:
                    try:
                        blob = inner.openstream(s).read()
                    except Exception:
                        continue
                    rep, cnt = try_patterns(blob, sensitive)
                    if cnt > 0:
                        hits += cnt
                        cur = cur.replace(blob, rep, 1)
                if hits > 0:
                    return cur, hits
            except Exception:
                pass

    # deflate/zlib 스캔
    for kind, off in scan_deflate(raw):
        r = decomp_at(raw, off, kind)
        if not r:
            continue
        dec, consumed = r
        rep_dec, cnt = try_patterns(dec, sensitive)
        if cnt == 0:
            continue
        if kind == "gzip":
            continue
        comp = recompress(kind, rep_dec)
        if comp is None:
            continue
        new_raw = patch_seg(raw, off, consumed, comp)
        if new_raw is None:
            continue
        hits += cnt
        return new_raw, hits

    # 그냥 raw에서 직접 교체
    rep, cnt = try_patterns(raw, sensitive)
    return rep, cnt


# ─────────────────────────────
# OLE 구조 유틸
# ─────────────────────────────
def _direntry_for(ole: olefile.OleFileIO, path: Tuple[str, ...]):
    try:
        sid = ole._find(path)
        if isinstance(sid, int):
            return ole.direntries[sid]
        return sid
    except Exception:
        return None

def _collect_ministream_offsets(ole: olefile.OleFileIO) -> List[int]:
    root = getattr(ole, "root", None)
    if root is None:
        return []
    sec_size = ole.sector_size
    fat = ole.fat
    s = root.isectStart
    out = []
    while s not in (-1, olefile.ENDOFCHAIN) and 0 <= s < len(fat):
        out.append((s + 1) * sec_size)
        s = fat[s]
        if len(out) > 65536:
            break
    return out

def _overwrite_bigfat(ole, container, start, new_raw):
    sec_size = ole.sector_size
    fat = ole.fat
    s = start
    pos = wrote = 0
    while s not in (-1, olefile.ENDOFCHAIN) and pos < len(new_raw):
        off = (s + 1) * sec_size
        chunk = new_raw[pos:pos + sec_size]
        container[off:off + len(chunk)] = chunk
        pos += len(chunk)
        wrote += len(chunk)
        s = fat[s]
    return wrote

def _overwrite_minifat_chain(ole, container, mini_start, new_raw):
    ole.loadminifat()
    mini_size = ole.mini_sector_size
    minifat = getattr(ole, "minifat", [])
    ministream_offsets = _collect_ministream_offsets(ole)
    if not ministream_offsets or not minifat:
        return 0

    pos = wrote = 0
    s = mini_start
    while s not in (-1, olefile.ENDOFCHAIN) and pos < len(new_raw):
        mini_off = s * mini_size
        big_idx = mini_off // ole.sector_size
        within = mini_off % ole.sector_size
        if big_idx >= len(ministream_offsets):
            break
        file_off = ministream_offsets[big_idx] + within
        chunk = new_raw[pos:pos + mini_size]
        container[file_off:file_off + len(chunk)] = chunk
        pos += len(chunk)
        wrote += len(chunk)
        s = minifat[s]
    return wrote


# ─────────────────────────────
# 문단 텍스트 추출기
# ─────────────────────────────
def _iter_para_text_records(section_dec: bytes):
    off, n = 0, len(section_dec)
    while off + 4 <= n:
        hdr = struct.unpack_from("<I", section_dec, off)[0]
        tag = hdr & 0x3FF
        size = (hdr >> 20) & 0xFFF
        off += 4
        if size < 0 or off + size > n:
            break
        payload = section_dec[off:off + size]
        if tag == TAG_PARA_TEXT:
            yield payload
        off += size

def extract_text(file_bytes: bytes) -> dict:
    texts = []
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        for path in ole.listdir(streams=True, storages=False):
            if not (len(path) >= 2 and path[0] == "BodyText" and path[1].startswith("Section")):
                continue
            raw = ole.openstream(path).read()
            dec, _ = _decompress(raw)
            for payload in _iter_para_text_records(dec):
                try:
                    texts.append(payload.decode("utf-16le", "ignore"))
                except:
                    pass
    full = "\n".join(texts)
    return {"full_text": full, "pages": [{"page": 1, "text": full}]}


# ─────────────────────────────
# 이미지 레코드 스캔
# ─────────────────────────────
def _iter_picture_records(section_dec: bytes):
    off, n = 0, len(section_dec)
    while off + 4 <= n:
        hdr = struct.unpack_from("<I", section_dec, off)[0]
        tag = hdr & 0x3FF
        size = (hdr >> 20) & 0xFFF
        off += 4
        if off + size > n:
            break
        if tag == TAG_PICTURE:
            yield section_dec[off:off + size]
        off += size


# ─────────────────────────────
# 메인 레닥션
# ─────────────────────────────
def redact(file_bytes: bytes) -> bytes:
    print("레닥션 시작")
    container = bytearray(file_bytes)

    # 텍스트 기반 민감어 수집
    full_raw = extract_text(file_bytes)["full_text"]
    full_norm = normalization_text(full_raw)
    targets = [t for t in sorted(
        {frag for _,__,frag,__ in ((s,e,full_norm[s:e],r) for s,e,_,r in find_sensitive_spans(full_norm)) if frag.strip()},
        key=lambda x: (-len(x), x)
    )]

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        streams = ole.listdir(streams=True, storages=False)
        cutoff = getattr(ole, "minisector_cutoff", 4096)

        # BodyText 레닥션 (문단 텍스트)
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
                        seg, _ = replace_bytes_with_enc(seg, t, "utf-16le")
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

        # BinData 처리 (이미지·OLE·압축 포함)
        for path in streams:
            if not (len(path) >= 2 and path[0] == "BinData"):
                continue

            raw = ole.openstream(path).read()
            rep = raw
            hit_total = 0

            for t in targets:
                rep2, hits = process_bindata(rep, t)
                rep = rep2
                hit_total += hits

            if hit_total == 0:
                continue

            entry = _direntry_for(ole, tuple(path))
            if entry:
                if entry.size < cutoff:
                    _overwrite_minifat_chain(ole, container, entry.isectStart, rep)
                else:
                    _overwrite_bigfat(ole, container, entry.isectStart, rep)

        # PrvText 처리
        for path in streams:
            if len(path) != 1:
                continue
            name = path[0].lower()

            if "prv" in name and "text" in name:
                raw = ole.openstream(path).read()
                rep = raw
                for t in targets:
                    rep2, _ = replace_bytes_with_enc(rep, t, "utf-16le")
                    rep = rep2
                if len(rep) < len(raw):
                    rep = rep + b"\x00" * (len(raw) - len(rep))
                elif len(rep) > len(raw):
                    rep = rep[:len(raw)]

                entry = _direntry_for(ole, path)
                if entry:
                    if entry.size < cutoff:
                        _overwrite_minifat_chain(ole, container, entry.isectStart, rep)
                    else:
                        _overwrite_bigfat(ole, container, entry.isectStart, rep)

        # PrvImage 삭제
        for path in streams:
            if len(path) == 1:
                name = path[0].lower()
                if "prv" in name and "image" in name:
                    raw = ole.openstream(path).read()
                    rep = b"\x00" * len(raw)
                    entry = _direntry_for(ole, path)
                    if entry:
                        if entry.size < cutoff:
                            _overwrite_minifat_chain(ole, container, entry.isectStart, rep)
                        else:
                            _overwrite_bigfat(ole, container, entry.isectStart, rep)

    return bytes(container)
