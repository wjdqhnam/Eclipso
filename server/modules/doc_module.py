import io
import os
import re
import struct
import tempfile
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans
from server.modules.doc_chart import redact_workbooks, extract_chart_text


# 리틀엔디언 헬퍼
def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


# Word 구조 읽기
def get_table_stream(word_data: bytes, ole: olefile.OleFileIO) -> Optional[str]:
    fib_flags = le16(word_data, 0x000A)
    fWhichTblStm = (fib_flags & 0x0200) != 0
    tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"
    return tbl_name if ole.exists(tbl_name) else None


def read_streams(file_bytes: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
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
    return table_data[fcClx:fcClx + lcbClx]


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
            return clx[i:i + lcb]
        else:
            break
    return b""


def parse_plcpcd(plcpcd: bytes) -> List[Dict[str, Any]]:
    size = len(plcpcd)
    if size < 4 or (size - 4) % 12 != 0:
        return []
    n = (size - 4) // 12
    aCp = [le32(plcpcd, 4 * i) for i in range(n + 1)]
    pcd_off = 4 * (n + 1)

    pieces = []
    for k in range(n):
        pcd_bytes = plcpcd[pcd_off + 8*k : pcd_off + 8*(k+1)]
        fc_raw = le32(pcd_bytes, 2)
        fc = fc_raw & 0x3FFFFFFF
        fCompressed = (fc_raw & 0x40000000) != 0
        cp_start, cp_end = aCp[k], aCp[k + 1]
        char_count = cp_end - cp_start
        byte_count = char_count if fCompressed else char_count * 2
        pieces.append({
            "index": k,
            "fc": fc,
            "byte_count": byte_count,
            "fCompressed": fCompressed,
            "cp_start": cp_start,
            "cp_end": cp_end
        })
    return pieces


def decode_piece(chunk: bytes, fCompressed: bool) -> str:
    try:
        return chunk.decode("cp1252" if fCompressed else "utf-16le", errors="ignore")
    except Exception:
        return ""



# Word 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
    try:
        word_data, table_data = read_streams(file_bytes)
        if not word_data or not table_data:
            return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}

        # Word 본문
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


        # Chart 텍스트 합치기
        chart_texts = extract_chart_text(file_bytes)
        print("=== [DEBUG] chart_texts ===", chart_texts)  #디버깅용

        if chart_texts:
            print(f"[INFO] extracted {len(chart_texts)} chart texts")
            raw_text = raw_word_text + "\n" + "\n".join(chart_texts)
        else:
            raw_text = raw_word_text

        normalized = normalization_text(raw_text)

        return {
            "full_text": normalized,
            "raw_text": raw_text,
            "pages": [{"page": 1, "text": normalized}]
        }

    except Exception as e:
        print(f"[ERR] DOC 추출 중 예외: {e}")
        return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}




# 탐지 span 보정(분리)
def split_matches(matches, text):
    new_matches = []
    for s, e, val, meta in matches:
        snippet = text[s:e]
        if "\r\r" in snippet or "\n\n" in snippet:
            parts = re.split(r'[\r\n]{2,}', snippet)
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



def _mask_keep_rules(v: str) -> str:
    out = []
    for ch in v:
        if ch == '-':
            out.append(ch)
        elif ch.isalnum() or ch in '._':
            out.append('*')
        else:
            out.append(ch)
    return ''.join(out)


def _mask_email(v: str) -> str:
    out = []
    in_entity = False
    for ch in v:
        if ch == '&':
            in_entity = True
            out.append(ch)
            continue
        if in_entity:
            out.append(ch)
            if ch == ';':
                in_entity = False
            continue

        if ch in ('@', '-'):
            out.append(ch)
        else:
            out.append('*')
    return ''.join(out)


def _mask_value(rule: str, v: str) -> str:
    r = (rule or '').lower()
    if r == 'email' or 'email' in r:
        return _mask_email(v)
    return _mask_keep_rules(v)


# Word 본문 레닥션
def replace_text(file_bytes: bytes, targets: list[tuple[int, int, str]], replacement_char: str = "*") -> bytes:

    try:
        word_data, table_data = read_streams(file_bytes)
        if not word_data or not table_data:
            raise ValueError("WordDocument 또는 Table 스트림을 읽을 수 없습니다")

        plcpcd = extract_plcpcd(get_clx_data(word_data, table_data) or b"")
        pieces = parse_plcpcd(plcpcd)

        # CP 범위 -> (fc, bpc) 매핑
        piece_spans: list[tuple[int, int, int, int]] = []
        cur = 0
        for p in pieces:
            fc_base = p["fc"]
            bpc = 1 if p["fCompressed"] else 2
            cp_len = p["cp_end"] - p["cp_start"]
            piece_spans.append((cur, cur + cp_len, fc_base, bpc))
            cur += cp_len

        replaced = bytearray(word_data)

        for s, e, rule in targets:
            if e <= s:
                continue
            for text_start, text_end, fc_base, bpc in piece_spans:
                if s >= text_end or e <= text_start:
                    continue

                local_start, local_end = max(s, text_start), min(e, text_end)
                byte_start = fc_base + (local_start - text_start) * bpc
                byte_len = (local_end - local_start) * bpc

                # 원본 구간을 문자열로 복원한 뒤, 규칙별로 동일 길이 마스킹
                seg_bytes = bytes(replaced[byte_start:byte_start + byte_len])
                if bpc == 2:
                    seg_text = seg_bytes.decode("utf-16le", errors="replace")
                    masked_text = _mask_value(rule, seg_text)
                    masked_bytes = masked_text.encode("utf-16le")
                else:
                    seg_text = seg_bytes.decode("latin-1", errors="replace")
                    masked_text = _mask_value(rule, seg_text)
                    masked_bytes = masked_text.encode("latin-1", errors="replace")

                # 길이가 달라지면 기존 방식(전부 마스킹)으로 폴백
                if len(masked_bytes) != byte_len:
                    mask = (
                        replacement_char.encode("utf-16le")[:2] * (byte_len // 2)
                        if bpc == 2
                        else replacement_char.encode("latin-1")[:1] * byte_len
                    )
                    replaced[byte_start:byte_start + byte_len] = mask
                else:
                    replaced[byte_start:byte_start + byte_len] = masked_bytes

        return create_new_ole_file(file_bytes, bytes(replaced))
    except Exception as e:
        print(f"[ERR] 텍스트 치환 중 오류: {e}")
        return file_bytes


_OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_DIFSECT = 0xFFFFFFFC


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _sect_off(sector: int, sector_size: int) -> int:
    # OLE: sector 0 starts right after 512-byte header
    return (sector + 1) * sector_size


def _read_sector(data: bytes, sector: int, sector_size: int) -> bytes:
    off = _sect_off(sector, sector_size)
    end = off + sector_size
    if off < 0 or end > len(data):
        return b""
    return data[off:end]


def _iter_fat_chain(start_sector: int, fat: List[int], *, max_steps: int = 2_000_000):
    # generator of sectors in the chain
    seen = set()
    s = int(start_sector)
    steps = 0
    while s not in (_ENDOFCHAIN, _FREESECT) and s >= 0 and s < len(fat):
        if s in seen:
            break  # loop guard
        seen.add(s)
        yield s
        s = int(fat[s])
        steps += 1
        if steps >= max_steps:
            break


def _collect_fat_sectors(data: bytes, sector_size: int) -> List[int]:
    # DIFAT header entries: 109 * 4 bytes starting at 0x4C
    fat_sectors: List[int] = []
    for i in range(109):
        v = _u32(data, 0x4C + i * 4)
        if v in (_FREESECT, _ENDOFCHAIN):
            continue
        fat_sectors.append(int(v))

    difat_start = _u32(data, 0x44)
    num_difat = _u32(data, 0x48)

    if difat_start in (_FREESECT, _ENDOFCHAIN) or num_difat == 0:
        return fat_sectors

    next_difat = int(difat_start)
    visited = set()
    for _ in range(int(num_difat) + 1):
        if next_difat in visited or next_difat in (_FREESECT, _ENDOFCHAIN):
            break
        visited.add(next_difat)
        sec = _read_sector(data, next_difat, sector_size)
        if not sec:
            break
        count = sector_size // 4
        for j in range(count - 1):
            v = struct.unpack_from("<I", sec, j * 4)[0]
            if v in (_FREESECT, _ENDOFCHAIN):
                continue
            fat_sectors.append(int(v))
        next_difat = struct.unpack_from("<I", sec, (count - 1) * 4)[0]
    return fat_sectors


def _build_fat(data: bytes, sector_size: int) -> List[int]:
    fat_sectors = _collect_fat_sectors(data, sector_size)
    out: List[int] = []
    for fs in fat_sectors:
        sec = _read_sector(data, fs, sector_size)
        if not sec:
            continue
        for i in range(sector_size // 4):
            out.append(struct.unpack_from("<I", sec, i * 4)[0])
    return out


def _read_stream_from_chain(data: bytes, sector_size: int, fat: List[int], start_sector: int, size: Optional[int] = None) -> bytes:
    chunks: List[bytes] = []
    for s in _iter_fat_chain(start_sector, fat):
        chunks.append(_read_sector(data, s, sector_size))
    raw = b"".join(chunks)
    if size is not None and size >= 0:
        return raw[: int(size)]
    return raw


def _find_dir_entry(data: bytes, sector_size: int, fat: List[int], name: str) -> Optional[Tuple[int, int]]:
    # returns (start_sector, size) for a stream
    dir_start = _u32(data, 0x30)
    if dir_start in (_FREESECT, _ENDOFCHAIN):
        return None

    dir_raw = _read_stream_from_chain(data, sector_size, fat, int(dir_start), None)
    if not dir_raw:
        return None

    target = name.strip()
    for off in range(0, len(dir_raw) - 128 + 1, 128):
        ent = dir_raw[off : off + 128]
        try:
            name_len = _u16(ent, 64)
            if name_len < 2 or name_len > 64:
                continue
            nm = ent[: name_len - 2].decode("utf-16le", errors="ignore").rstrip("\x00")
            if nm != target:
                continue
            # stream start sector + size
            start_sector = _u32(ent, 116)
            size = _u64(ent, 120)
            return int(start_sector), int(size)
        except Exception:
            continue
    return None


def _overwrite_stream_in_ole(original_file_bytes: bytes, stream_name: str, new_stream_bytes: bytes) -> bytes:
    data = bytes(original_file_bytes)
    if len(data) < 512 or data[:8] != _OLE_MAGIC:
        return original_file_bytes

    sector_shift = _u16(data, 0x1E)
    sector_size = 1 << int(sector_shift)
    if sector_size not in (512, 1024, 2048, 4096):
        return original_file_bytes

    fat = _build_fat(data, sector_size)
    if not fat:
        return original_file_bytes

    entry = _find_dir_entry(data, sector_size, fat, stream_name)
    if not entry:
        return original_file_bytes
    start_sector, stream_size = entry

    if int(stream_size) != len(new_stream_bytes):
        return original_file_bytes

    out = bytearray(data)
    pos = 0
    for s in _iter_fat_chain(start_sector, fat):
        if pos >= stream_size:
            break
        off = _sect_off(s, sector_size)
        take = min(sector_size, stream_size - pos)
        if off < 0 or off + take > len(out):
            return original_file_bytes
        out[off : off + take] = new_stream_bytes[pos : pos + take]
        pos += take

    if pos != stream_size:
        # chain shorter than expected
        return original_file_bytes

    return bytes(out)


def create_new_ole_file(original_file_bytes: bytes, new_word_data: bytes) -> bytes:

    try:
        return _overwrite_stream_in_ole(original_file_bytes, "WordDocument", new_word_data)
    except Exception as e:
        print(f"[ERR] OLE overwrite 중 오류: {e}")
        return original_file_bytes



def redact_word_document(file_bytes: bytes, spans: Optional[List[Dict[str, Any]]] = None) -> bytes:
    try:
        data = extract_text(file_bytes)
        raw_text = data.get("raw_text", "")
        if not raw_text:
            return file_bytes

        norm_text, index_map = normalization_index(raw_text)
        matches = find_sensitive_spans(norm_text)
        matches = split_matches(matches, norm_text)

        span_ranges: List[Tuple[int, int]] = []
        if spans and isinstance(spans, list):
            n = len(norm_text)
            for sp in spans:
                if not isinstance(sp, dict):
                    continue
                s = sp.get("start")
                e = sp.get("end")
                if s is None or e is None:
                    continue
                try:
                    s = int(s)
                    e = int(e)
                except Exception:
                    continue
                s = max(0, min(n, s))
                e = max(0, min(n, e))
                if e <= s:
                    continue
                span_ranges.append((s, e))
        if span_ranges:
            for s, e in span_ranges:
                matches.append((s, e, norm_text[s:e], "SPAN"))

        targets = []
        def _map_pos(idx: int) -> Optional[int]:
            if idx in index_map:
                return index_map[idx]
            j = idx
            while j >= 0 and j not in index_map:
                j -= 1
            if j >= 0 and j in index_map:
                return index_map[j]
            j = idx
            while j < len(norm_text) and j not in index_map:
                j += 1
            if j < len(norm_text) and j in index_map:
                return index_map[j]
            return None

        for s, e, val, _ in matches:
            if not isinstance(s, int) or not isinstance(e, int) or e <= s:
                continue
            start = _map_pos(s)
            end0 = _map_pos(e - 1)
            if start is None or end0 is None:
                continue
            end = end0 + 1
            if end <= start:
                end = start + max(1, (e - s))
            targets.append((start, end, val))
        return replace_text(file_bytes, targets)

    except Exception as e:
        print(f"[ERR] WordDocument 레닥션 중 예외: {e}")
        return file_bytes


def redact(file_bytes: bytes, spans: Optional[List[Dict[str, Any]]] = None) -> bytes:
    redacted_doc = redact_word_document(file_bytes, spans=spans)
    redacted_doc = redact_workbooks(redacted_doc)
    return redacted_doc
