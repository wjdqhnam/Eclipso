from __future__ import annotations
import io, zlib, struct
from typing import List, Tuple
import olefile

from server.core.matching import find_sensitive_spans  

TAG_PARA_TEXT = 67

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

def _direntry_for(ole: olefile.OleFileIO, path: Tuple[str, ...]):
    try:
        sid_or_entry = ole._find(path)
        if isinstance(sid_or_entry, int):
            i = sid_or_entry
            return ole.direntries[i] if 0 <= i < len(ole.direntries) else None
        return sid_or_entry
    except Exception:
        return None

def _collect_ministream_offsets(ole: olefile.OleFileIO) -> List[int]:
    root = getattr(ole, "root", None)
    if root is None:
        return []
    sec_size = ole.sector_size
    fat = ole.fat
    s = root.isectStart
    out: List[int] = []
    while s not in (-1, olefile.ENDOFCHAIN) and 0 <= s < len(fat):
        out.append((s + 1) * sec_size)
        s = fat[s]
        if len(out) > 65536:
            break
    return out

def _overwrite_bigfat(ole: olefile.OleFileIO, container: bytearray, start_sector: int, new_raw: bytes) -> int:
    sec_size = ole.sector_size
    fat = ole.fat
    s = start_sector
    pos = wrote = 0
    while s not in (-1, olefile.ENDOFCHAIN) and 0 <= s < len(fat) and pos < len(new_raw):
        off = (s + 1) * sec_size
        chunk = new_raw[pos : pos + sec_size]
        container[off : off + len(chunk)] = chunk
        pos += len(chunk)
        wrote += len(chunk)
        s = fat[s]
    return wrote

def _overwrite_minifat_chain(ole: olefile.OleFileIO, container: bytearray, mini_start: int, new_raw: bytes) -> int:
    ole.loadminifat()
    mini_size = ole.mini_sector_size
    minifat = getattr(ole, "minifat", [])
    ministream_offsets = _collect_ministream_offsets(ole)
    if not ministream_offsets or not minifat:
        return 0
    pos = wrote = 0
    s = mini_start
    while s not in (-1, olefile.ENDOFCHAIN) and 0 <= s < len(minifat) and pos < len(new_raw):
        mini_off = s * mini_size
        big_index = mini_off // ole.sector_size
        within = mini_off % ole.sector_size
        if big_index >= len(ministream_offsets):
            break
        file_off = ministream_offsets[big_index] + within
        chunk = new_raw[pos : pos + mini_size]
        container[file_off : file_off + len(chunk)] = chunk
        pos += len(chunk)
        wrote += len(chunk)
        s = minifat[s]
        if wrote > 64 * 1024 * 1024:
            break
    return wrote

def _iter_para_text_records(section_dec: bytes):
    off, n = 0, len(section_dec)
    while off + 4 <= n:
        hdr = struct.unpack_from("<I", section_dec, off)[0]
        tag = hdr & 0x3FF
        size = (hdr >> 20) & 0xFFF
        off += 4
        if size < 0 or off + size > n:
            break
        payload = section_dec[off : off + size]
        if tag == TAG_PARA_TEXT:
            yield payload
        off += size

def extract_text(file_bytes: bytes) -> dict:
    texts: List[str] = []
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        for path in ole.listdir(streams=True, storages=False):
            if not (len(path) >= 2 and path[0] == "BodyText" and path[1].startswith("Section")):
                continue
            raw = ole.openstream(path).read()
            dec, _ = _decompress(raw)
            for payload in _iter_para_text_records(dec):
                try:
                    texts.append(payload.decode("utf-16le", "ignore"))
                except Exception:
                    pass
    full = "\n".join(texts)
    return {"full_text": full, "pages": [{"page": 1, "text": full}]}

def _collect_targets_by_regex(text: str) -> List[str]:
    res = find_sensitive_spans(text) 
    targets: List[str] = []
    for s, e, _val, _rule in res:
        if isinstance(s, int) and isinstance(e, int) and e > s:
            frag = text[s:e]
            if frag and len(frag.strip()) >= 1:
                targets.append(frag)
    targets = sorted(set(targets), key=lambda x: (-len(x), x))
    return targets

def _replace_utf16le_keep_len(buf: bytes, t: str) -> Tuple[bytes, int]:
    if not t:
        return buf, 0
    pat = t.encode("utf-16le", "ignore")
    rep = ("*" * len(t)).encode("utf-16le")
    count = buf.count(pat)
    if count:
        buf = buf.replace(pat, rep)
    return buf, count

def _replace_in_bindata(raw: bytes, t: str) -> Tuple[bytes, int]:
    total = 0
    out = raw
    for enc in ("utf-16le", "utf-8", "cp949"):
        try:
            pat = t.encode(enc, "ignore")
            if not pat:
                continue
            rep = (("*" * len(t)).encode("utf-16le") if enc == "utf-16le" else b"*" * len(pat))
            hits = out.count(pat)
            if hits:
                out = out.replace(pat, rep)
                total += hits
        except Exception:
            pass
    return out, total

def redact(file_bytes: bytes) -> bytes:
    container = bytearray(file_bytes)
    full = extract_text(file_bytes)["full_text"]
    targets = _collect_targets_by_regex(full) 

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        streams = ole.listdir(streams=True, storages=False)
        cutoff = getattr(ole, "minisector_cutoff", 4096)

        # BodyText/Section*
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
                if tag == TAG_PARA_TEXT and size > 0 and targets:
                    seg = bytes(buf[off:off+size])
                    for t in targets:
                        seg, _ = _replace_utf16le_keep_len(seg, t)
                    buf[off:off+size] = seg
                off += size

            new_raw = _recompress(bytes(buf), mode)
            if len(new_raw) < len(raw):
                new_raw = new_raw + b"\x00" * (len(raw) - len(new_raw))
            elif len(new_raw) > len(raw):
                new_raw = new_raw[:len(raw)]

            entry = _direntry_for(ole, tuple(path))
            if not entry:
                continue
            if entry.size < cutoff:
                _overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
            else:
                _overwrite_bigfat(ole, container, entry.isectStart, new_raw)

        # BinData/*.OLE
        for path in streams:
            if not (len(path) >= 2 and path[0] == "BinData" and path[1].endswith(".OLE")):
                continue
            raw = ole.openstream(path).read()
            rep = raw
            hit = 0
            for t in targets:
                rep, c = _replace_in_bindata(rep, t)
                hit += c
            if hit <= 0 or len(rep) != len(raw):
                continue
            entry = _direntry_for(ole, tuple(path))
            if not entry:
                continue
            _overwrite_bigfat(ole, container, entry.isectStart, rep)

    return bytes(container)
