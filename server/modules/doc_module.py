import io
import os
import re
import struct
import tempfile
import hashlib
from typing import List, Dict, Any, Tuple, Optional

import olefile

from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans
from server.modules.doc_chart import redact_workbooks, extract_chart_text


# ENV (디버그/덤프)
def _env_on(*names: str, default: str = "0") -> bool:
    v = None
    for nm in names:
        vv = os.getenv(nm)
        if vv is not None and vv != "":
            v = vv
            break
    if v is None:
        v = default
    try:
        return bool(int(str(v).strip()))
    except Exception:
        return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


DOC_DEBUG_IMAGE_LOC = _env_on("DOC_DEBUG_IMAGE_LOC", "DOC_DEBUG_IMAGES", default="0")
DOC_DUMP_IMAGES = _env_on("DOC_DUMP_IMAGES", "DOC_SAVE_IMAGES", default="0")
DOC_DUMP_DIR = os.getenv("DOC_DUMP_DIR") or os.getenv("DOC_IMAGES_DIR") or "image_dumps"


def _dbg(msg: str) -> None:
    if DOC_DEBUG_IMAGE_LOC:
        print(f"[DOC][DBG] {msg}")


# 리틀엔디언 헬퍼
def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def le32s(b: bytes, off: int) -> int:
    return struct.unpack_from("<i", b, off)[0]


# Word 구조 읽기
def get_table_stream(word_data: bytes, ole: olefile.OleFileIO) -> Optional[str]:
    fib_flags = le16(word_data, 0x000A)
    fWhichTblStm = (fib_flags & 0x0200) != 0
    tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"
    return tbl_name if ole.exists(tbl_name) else None


def read_streams(file_bytes: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    """WordDocument / Table 스트림 모두 읽기"""
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("WordDocument"):
                return None, None
            word_data = ole.openstream("WordDocument").read()
            tbl_name = get_table_stream(word_data, ole)
            table_data = ole.openstream(tbl_name).read() if tbl_name else None
            return word_data, table_data
    except Exception:
        return None, None


# PlcPcd / CLX 파싱
def get_clx_data(word_data: bytes, table_data: bytes) -> Optional[bytes]:
    fcClx, lcbClx = le32(word_data, 0x01A2), le32(word_data, 0x01A6)
    if not table_data or fcClx + lcbClx > len(table_data):
        return None
    return table_data[fcClx : fcClx + lcbClx]


def extract_plcpcd(clx: bytes) -> bytes:
    i = 0
    while i < len(clx):
        tag = clx[i]
        i += 1
        if tag == 0x01:
            cb = struct.unpack_from("<H", clx, i)[0]
            i += 2 + cb
        elif tag == 0x02:
            lcb = struct.unpack_from("<I", clx, i)[0]
            i += 4
            return clx[i : i + lcb]
        else:
            break
    return b""


def parse_plcpcd(plcpcd: bytes) -> List[Dict[str, Any]]:
    """PlcPcd 구조를 CP 구간 / fc 기반으로 파싱"""
    size = len(plcpcd)
    if size < 4 or (size - 4) % 12 != 0:
        return []
    n = (size - 4) // 12
    aCp = [le32(plcpcd, 4 * i) for i in range(n + 1)]
    pcd_off = 4 * (n + 1)

    pieces = []
    for k in range(n):
        pcd_bytes = plcpcd[pcd_off + 8 * k : pcd_off + 8 * (k + 1)]
        fc_raw = le32(pcd_bytes, 2)
        fc = fc_raw & 0x3FFFFFFF
        fCompressed = (fc_raw & 0x40000000) != 0
        cp_start, cp_end = aCp[k], aCp[k + 1]
        char_count = cp_end - cp_start
        byte_count = char_count if fCompressed else char_count * 2
        pieces.append(
            {
                "index": k,
                "fc": fc,
                "byte_count": byte_count,
                "fCompressed": fCompressed,
                "cp_start": cp_start,
                "cp_end": cp_end,
            }
        )
    return pieces


def decode_piece(chunk: bytes, fCompressed: bool) -> str:
    try:
        return chunk.decode("cp1252" if fCompressed else "utf-16le", errors="ignore")
    except Exception:
        return ""


# 이미지: 시그니처 스캐닝(휴리스틱) + sprmCPicLocation(휴리스틱 보강)
PNG_SIG = b"\x89PNG\r\n\x1a\n"
JPG_SIG = b"\xFF\xD8\xFF"
GIF87 = b"GIF87a"
GIF89 = b"GIF89a"
BMP_SIG = b"BM"
WMF_SIG = b"\xD7\xCD\xC6\x9A"


def _find_all(buf: bytes, needle: bytes, limit: int = 10_000) -> List[int]:
    out: List[int] = []
    if not needle:
        return out
    i = 0
    while True:
        j = buf.find(needle, i)
        if j < 0:
            break
        out.append(j)
        if len(out) >= limit:
            break
        i = j + 1
    return out


def _scan_image_sigs(buf: bytes) -> List[Tuple[str, int]]:
    hits: List[Tuple[str, int]] = []
    for off in _find_all(buf, PNG_SIG, limit=50_000):
        hits.append(("PNG", off))
    for off in _find_all(buf, JPG_SIG, limit=50_000):
        hits.append(("JPG", off))
    for off in _find_all(buf, GIF87, limit=50_000):
        hits.append(("GIF", off))
    for off in _find_all(buf, GIF89, limit=50_000):
        hits.append(("GIF", off))
    for off in _find_all(buf, BMP_SIG, limit=50_000):
        hits.append(("BMP", off))
    for off in _find_all(buf, WMF_SIG, limit=50_000):
        hits.append(("WMF", off))
    hits.sort(key=lambda x: x[1])
    return hits


def _extract_png(buf: bytes, off: int) -> Optional[bytes]:
    if off < 0 or off + 8 > len(buf) or buf[off : off + 8] != PNG_SIG:
        return None
    p = off + 8
    while p + 12 <= len(buf):
        ln = struct.unpack_from(">I", buf, p)[0]
        typ = buf[p + 4 : p + 8]
        p2 = p + 12 + ln
        if p2 > len(buf):
            break
        if typ == b"IEND":
            return buf[off:p2]
        p = p2
    return None


def _extract_jpg(buf: bytes, off: int) -> Optional[bytes]:
    if off < 0 or off + 3 > len(buf) or buf[off : off + 2] != b"\xFF\xD8":
        return None
    end = buf.find(b"\xFF\xD9", off + 2)
    if end < 0:
        return None
    return buf[off : end + 2]


def _extract_gif(buf: bytes, off: int) -> Optional[bytes]:
    if off < 0 or off + 6 > len(buf):
        return None
    if buf[off : off + 6] not in (GIF87, GIF89):
        return None
    end = buf.find(b"\x3B", off + 6)
    if end < 0:
        return None
    return buf[off : end + 1]


def _extract_bmp(buf: bytes, off: int) -> Optional[bytes]:
    if off < 0 or off + 14 > len(buf) or buf[off : off + 2] != BMP_SIG:
        return None
    try:
        sz = struct.unpack_from("<I", buf, off + 2)[0]
        end = off + sz
        if 0 < sz and end <= len(buf):
            return buf[off:end]
    except Exception:
        return None
    return None


def _extract_blob(buf: bytes, kind: str, off: int, next_off: Optional[int] = None) -> Optional[bytes]:
    if kind == "PNG":
        b = _extract_png(buf, off)
        if b is not None:
            return b
    elif kind == "JPG":
        b = _extract_jpg(buf, off)
        if b is not None:
            return b
    elif kind == "GIF":
        b = _extract_gif(buf, off)
        if b is not None:
            return b
    elif kind == "BMP":
        b = _extract_bmp(buf, off)
        if b is not None:
            return b

    cap = 10 * 1024 * 1024  # 10MB
    end = min(len(buf), off + cap)
    if next_off is not None and next_off > off:
        end = min(end, next_off)
    if end <= off:
        return None
    return buf[off:end]


def _sprm_cpiclocation_offsets(word_data: bytes, data_len: int) -> List[int]:
    # opcode 0x6A03 (little-end) => b'\x03\x6A' + 4바이트 signed operand
    hits: List[int] = []
    pat = b"\x03\x6A"
    i = 0
    while True:
        j = word_data.find(pat, i)
        if j < 0:
            break
        if j + 6 <= len(word_data):
            off = le32s(word_data, j + 2)
            if 0 <= off < data_len:
                hits.append(off)
        i = j + 2
        if len(hits) > 20_000:
            break
    return sorted(set(hits))


def build_image_loc_summary(file_bytes: bytes) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "found": False,
        "streams": {},
        "data": {"exists": False, "len": 0, "sig_hits": 0, "by_type": {}},
        "objectpool": {"exists": False, "streams": 0, "sig_hits": 0, "by_type": {}},
        "sprmCPicLocation": {"hits": 0},
    }

    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            for path in ole.listdir(streams=True, storages=False):
                try:
                    nm = "/".join(path)
                    try:
                        sz = ole.get_size(path)
                    except Exception:
                        sz = None
                    if sz is not None:
                        summary["streams"][nm] = sz
                except Exception:
                    continue

            if not ole.exists("WordDocument"):
                return summary
            word_data = ole.openstream("WordDocument").read()

            if ole.exists("Data"):
                data = ole.openstream("Data").read()
                summary["data"]["exists"] = True
                summary["data"]["len"] = len(data)

                sigs = _scan_image_sigs(data)
                by: Dict[str, int] = {}
                for k, _off in sigs:
                    by[k] = by.get(k, 0) + 1
                summary["data"]["sig_hits"] = len(sigs)
                summary["data"]["by_type"] = by

                offs = _sprm_cpiclocation_offsets(word_data, len(data))
                summary["sprmCPicLocation"]["hits"] = len(offs)

            obj_streams = [p for p in ole.listdir(streams=True, storages=False) if p and p[0] == "ObjectPool"]
            if obj_streams:
                summary["objectpool"]["exists"] = True
                summary["objectpool"]["streams"] = len(obj_streams)
                by2: Dict[str, int] = {}
                hit2 = 0
                for p in obj_streams:
                    try:
                        raw = ole.openstream(p).read()
                    except Exception:
                        continue
                    sigs2 = _scan_image_sigs(raw)
                    hit2 += len(sigs2)
                    for k, _off in sigs2:
                        by2[k] = by2.get(k, 0) + 1
                summary["objectpool"]["sig_hits"] = hit2
                summary["objectpool"]["by_type"] = by2

            summary["found"] = bool(summary["data"]["sig_hits"] or summary["objectpool"]["sig_hits"])
            return summary
    except Exception as e:
        summary["error"] = repr(e)
        return summary


def extract_images(
    file_bytes: bytes,
    dump_dir: Optional[str] = None,
    include_b64: bool = False,
    max_images: int = 128,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": True, "images": []}
    if dump_dir is None:
        dump_dir = DOC_DUMP_DIR

    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("WordDocument"):
                return {"ok": False, "error": "WordDocument stream not found"}

            word_data = ole.openstream("WordDocument").read()
            data = ole.openstream("Data").read() if ole.exists("Data") else b""

            def emit(kind: str, blob: bytes, src: str, off: int) -> None:
                sha1 = hashlib.sha1(blob).hexdigest()
                rec: Dict[str, Any] = {
                    "type": kind,
                    "bytes": len(blob),
                    "sha1": sha1,
                    "source": src,
                    "offset": off,
                }
                if include_b64:
                    import base64
                    rec["b64"] = base64.b64encode(blob).decode("ascii")
                if dump_dir:
                    os.makedirs(dump_dir, exist_ok=True)
                    ext = kind.lower()
                    fn = f"doc_{len(out['images'])+1:04d}_{sha1[:10]}.{ext}"
                    fp = os.path.join(dump_dir, fn)
                    with open(fp, "wb") as f:
                        f.write(blob)
                    rec["path"] = fp
                out["images"].append(rec)

            if data:
                sigs = _scan_image_sigs(data)
                for idx, (k, off) in enumerate(sigs):
                    if len(out["images"]) >= max_images:
                        break
                    next_off = sigs[idx + 1][1] if idx + 1 < len(sigs) else None
                    blob = _extract_blob(data, k, off, next_off)
                    if blob:
                        emit(k, blob, "Data", off)

                offs = _sprm_cpiclocation_offsets(word_data, len(data))
                for base in offs[:5000]:
                    if len(out["images"]) >= max_images:
                        break
                    window = data[base : min(len(data), base + 4096)]
                    sigs2 = _scan_image_sigs(window)
                    if not sigs2:
                        continue
                    k2, rel = sigs2[0]
                    off2 = base + rel
                    blob2 = _extract_blob(data, k2, off2, None)
                    if blob2:
                        emit(k2, blob2, "Data(sprmCPicLocation)", off2)

            obj_streams = [p for p in ole.listdir(streams=True, storages=False) if p and p[0] == "ObjectPool"]
            for p in obj_streams:
                if len(out["images"]) >= max_images:
                    break
                try:
                    raw = ole.openstream(p).read()
                except Exception:
                    continue
                sigs3 = _scan_image_sigs(raw)
                for idx, (k, off) in enumerate(sigs3):
                    if len(out["images"]) >= max_images:
                        break
                    next_off = sigs3[idx + 1][1] if idx + 1 < len(sigs3) else None
                    blob = _extract_blob(raw, k, off, next_off)
                    if blob:
                        emit(k, blob, "ObjectPool/" + "/".join(p), off)

        seen = set()
        uniq = []
        for r in out["images"]:
            h = r.get("sha1")
            if h in seen:
                continue
            seen.add(h)
            uniq.append(r)
        out["images"] = uniq
        out["count"] = len(uniq)
        return out
    except Exception as e:
        return {"ok": False, "error": repr(e)}


# Word 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
    try:
        word_data, table_data = read_streams(file_bytes)
        if not word_data or not table_data:
            return {
                "full_text": "",
                "raw_text": "",
                "pages": [{"page": 1, "text": ""}],
                "image_loc": {"found": False, "error": "missing streams"},
            }

        clx = get_clx_data(word_data, table_data)
        plcpcd = extract_plcpcd(clx or b"")
        pieces = parse_plcpcd(plcpcd)

        texts = []
        for p in pieces:
            start, end = p["fc"], p["fc"] + p["byte_count"]
            if end > len(word_data):
                continue
            texts.append(decode_piece(word_data[start:end], p["fCompressed"]))

        raw_word_text = "".join(texts)

        chart_texts = extract_chart_text(file_bytes)
        if DOC_DEBUG_IMAGE_LOC:
            _dbg(f"chart_texts count={len(chart_texts) if chart_texts else 0}")

        raw_text = raw_word_text + ("\n" + "\n".join(chart_texts) if chart_texts else "")
        normalized = normalization_text(raw_text)

        out = {
            "full_text": normalized,
            "raw_text": raw_text,
            "pages": [{"page": 1, "text": normalized}],
        }

        try:
            loc = build_image_loc_summary(file_bytes)
            out["image_loc"] = loc
            if DOC_DEBUG_IMAGE_LOC:
                _dbg(f"image_loc: {loc}")
        except Exception as e:
            out["image_loc"] = {"found": False, "error": repr(e)}

        if DOC_DUMP_IMAGES:
            try:
                out["images_dump"] = extract_images(file_bytes, dump_dir=DOC_DUMP_DIR, include_b64=False)
            except Exception as e:
                out["images_dump"] = {"ok": False, "error": repr(e)}

        return out

    except Exception as e:
        print(f"[ERR] DOC 추출 중 예외: {e}")
        return {
            "full_text": "",
            "raw_text": "",
            "pages": [{"page": 1, "text": ""}],
            "image_loc": {"found": False, "error": repr(e)},
        }


# 탐지 span 보정(분리)
def split_matches(matches, text):
    new_matches = []
    for s, e, val, meta in matches:
        snippet = text[s:e]
        if "\r\r" in snippet or "\n\n" in snippet:
            parts = re.split(r"[\r\n]{2,}", snippet)
            cp_cursor = s
            for part in parts:
                if not part.strip():
                    cp_cursor += len(part) + 2
                    continue
                new_matches.append((cp_cursor, cp_cursor + len(part), part, meta))
                cp_cursor += len(part) + 2
        else:
            new_matches.append((s, e, val, meta))
    return new_matches


# Word 본문 레닥션
def replace_text(file_bytes: bytes, targets: List[Tuple[int, int, str]], replacement_char: str = "*") -> bytes:
    try:
        word_data, table_data = read_streams(file_bytes)
        if not word_data or not table_data:
            raise ValueError("WordDocument 또는 Table 스트림을 읽을 수 없습니다")

        plcpcd = extract_plcpcd(get_clx_data(word_data, table_data) or b"")
        pieces = parse_plcpcd(plcpcd)

        piece_spans = []
        cur = 0
        for p in pieces:
            fc_base = p["fc"]
            bpc = 1 if p["fCompressed"] else 2
            cp_len = p["cp_end"] - p["cp_start"]
            piece_spans.append((cur, cur + cp_len, fc_base, bpc))
            cur += cp_len

        replaced = bytearray(word_data)
        for s, e, _ in targets:
            for text_start, text_end, fc_base, bpc in piece_spans:
                if s >= text_end or e <= text_start:
                    continue
                local_start, local_end = max(s, text_start), min(e, text_end)
                byte_start = fc_base + (local_start - text_start) * bpc
                byte_len = (local_end - local_start) * bpc
                mask = (
                    (replacement_char.encode("utf-16le")[:2] * (byte_len // 2))
                    if bpc == 2
                    else replacement_char.encode("latin-1")[:1] * byte_len
                )
                replaced[byte_start : byte_start + byte_len] = mask

        return create_new_ole_file(file_bytes, bytes(replaced))
    except Exception as e:
        print(f"[ERR] 텍스트 치환 중 오류: {e}")
        return file_bytes


def create_new_ole_file(original_file_bytes: bytes, new_word_data: bytes) -> bytes:
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
            tmp.write(original_file_bytes)
            tmp_path = tmp.name

        with olefile.OleFileIO(tmp_path, write_mode=True) as ole:
            if not ole.exists("WordDocument"):
                return original_file_bytes
            old_len = len(ole.openstream("WordDocument").read())
            if len(new_word_data) != old_len:
                return original_file_bytes
            ole.write_stream("WordDocument", new_word_data)

        with open(tmp_path, "rb") as f:
            result = f.read()
        os.remove(tmp_path)
        return result
    except Exception as e:
        print(f"[ERR] OLE 교체 중 오류: {e}")
        return original_file_bytes


def redact_word_document(file_bytes: bytes) -> bytes:
    try:
        data = extract_text(file_bytes)
        raw_text = data.get("raw_text", "")
        if not raw_text:
            return file_bytes

        norm_text, index_map = normalization_index(raw_text)
        matches = find_sensitive_spans(norm_text)
        matches = split_matches(matches, norm_text)

        targets = []
        for s, e, val, _ in matches:
            if s in index_map and (e - 1) in index_map:
                start = index_map[s]
                end = index_map.get(e - 1, start) + 1
                if end <= start:
                    end = start + (e - s)
                targets.append((start, end, val))
        return replace_text(file_bytes, targets)
    except Exception as e:
        print(f"[ERR] WordDocument 레닥션 중 예외: {e}")
        return file_bytes


def redact(file_bytes: bytes) -> bytes:
    redacted_doc = redact_word_document(file_bytes)
    redacted_doc = redact_workbooks(redacted_doc)
    return redacted_doc
