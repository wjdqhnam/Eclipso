import io
import os
import re
import struct
import tempfile
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans


# ========== CONFIG ==========
DEBUG = True



# 유틸: 리틀엔디언 헬퍼
def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]



# Word 구조 읽기
def _get_table_stream_name(word_data: bytes, ole: olefile.OleFileIO) -> Optional[str]:
    fib_flags = le16(word_data, 0x000A)
    fWhichTblStm = (fib_flags & 0x0200) != 0
    tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"
    return tbl_name if ole.exists(tbl_name) else None


def _read_word_and_table_streams(file_bytes: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    """WordDocument / Table 스트림 모두 읽기"""
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("WordDocument"):
                return None, None
            word_data = ole.openstream("WordDocument").read()
            tbl_name = _get_table_stream_name(word_data, ole)
            table_data = ole.openstream(tbl_name).read() if tbl_name else None
            return word_data, table_data
    except Exception:
        return None, None



# PlcPcd / CLX 파싱
def _get_clx_data(word_data: bytes, table_data: bytes) -> Optional[bytes]:
    fcClx, lcbClx = le32(word_data, 0x01A2), le32(word_data, 0x01A6)
    if not table_data or fcClx + lcbClx > len(table_data):
        return None
    return table_data[fcClx:fcClx + lcbClx]


def _extract_plcpcd(clx: bytes) -> bytes:
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


def _parse_plcpcd(plcpcd: bytes) -> List[Dict[str, Any]]:
    """PlcPcd 구조를 CP 구간 / fc 기반으로 파싱"""
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


def _decode_piece(chunk: bytes, fCompressed: bool) -> str:
    """조각 텍스트 디코딩"""
    try:
        return chunk.decode("cp1252" if fCompressed else "utf-16le", errors="ignore")
    except Exception:
        return ""


# 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
    """WordDocument에서 전체 텍스트 추출"""
    try:
        word_data, table_data = _read_word_and_table_streams(file_bytes)
        if not word_data or not table_data:
            return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}

        clx = _get_clx_data(word_data, table_data)
        plcpcd = _extract_plcpcd(clx or b"")
        pieces = _parse_plcpcd(plcpcd)

        texts = []
        for p in pieces:
            start, end = p["fc"], p["fc"] + p["byte_count"]
            if end > len(word_data):
                continue
            texts.append(_decode_piece(word_data[start:end], p["fCompressed"]))

        raw_text = "".join(texts)
        normalized = normalization_text(raw_text)
        return {"full_text": normalized, "raw_text": raw_text, "pages": [{"page": 1, "text": normalized}]}
    except Exception as e:
        print(f"[ERR] DOC 추출 중 예외: {e}")
        return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}


# 탐지 span 보정(분리)
def _split_cross_paragraph_matches(matches, text):
    """\r\r 또는 \n\n 문단 경계를 포함한 매치를 자동으로 분리"""
    new_matches = []
    for s, e, val, meta in matches:
        snippet = text[s:e]
        # 문단 경계 포함 여부
        if "\r\r" in snippet or "\n\n" in snippet:
            # 두 개 이상 개행 기준으로 분리
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


# 바이트 치환 (레닥션)
def replace_text(file_bytes: bytes, targets: List[Tuple[int, int, str]], replacement_char: str = "*") -> bytes:
    """CP 좌표 기반으로 WordDocument 스트림 내 바이트 치환"""
    try:
        word_data, table_data = _read_word_and_table_streams(file_bytes)
        if not word_data or not table_data:
            raise ValueError("WordDocument 또는 Table 스트림을 읽을 수 없습니다")

        plcpcd = _extract_plcpcd(_get_clx_data(word_data, table_data) or b"")
        pieces = _parse_plcpcd(plcpcd)


        # CP 누적 계산
        piece_spans = []
        cur = 0

        for p in pieces:
            fc_base = p["fc"]
            bpc = 1 if p["fCompressed"] else 2
            start, end = p["fc"], p["fc"] + p["byte_count"]
            text = _decode_piece(word_data[start:end], p["fCompressed"])

            cp_len = p["cp_end"] - p["cp_start"]
            dec_len = len(text)
            diff = cp_len - dec_len

            if diff != 0 and abs(diff) <= 5:
                if DEBUG:
                    print(f"[CP-MISMATCH] piece#{p['index']} diff={diff} (cp_len={cp_len}, dec_len={dec_len})")

            text_start = cur
            text_end = cur + cp_len
            piece_spans.append((text_start, text_end, fc_base, bpc))

            # diff를 다음 cur에 누적
            cur += cp_len + (diff if abs(diff) <= 5 else 0)


        if DEBUG:
            print("\n[DEBUG] TARGET 목록")
            for s, e, *_ in targets:
                print(f"→ cp={s}-{e} len={e-s}")
            print("==============================")
            for i, (s, e, fc, bpc) in enumerate(piece_spans):
                print(f"piece{i}: cp={s}-{e}, fc={fc}, bpc={bpc}")
            print("==============================")

        replaced = bytearray(word_data)
        for s, e, _ in targets:
            for text_start, text_end, fc_base, bpc in piece_spans:
                if s >= text_end or e <= text_start:
                    continue
                local_start, local_end = max(s, text_start), min(e, text_end)
                if local_start >= local_end:
                    continue

                byte_start = fc_base + (local_start - text_start) * bpc
                byte_len = (local_end - local_start) * bpc
                mask = (replacement_char.encode("utf-16le")[:2] * (byte_len // 2)
                        if bpc == 2 else replacement_char.encode("latin-1")[:1] * byte_len)

                if DEBUG:
                    raw = replaced[byte_start:byte_start + byte_len]
                    try:
                        text = raw.decode("utf-16le") if bpc == 2 else raw.decode("latin-1", "ignore")
                    except Exception:
                        text = "[decode error]"
                    print(f"[REPLACE] cp={s}-{e}, bytes=({byte_start}-{byte_start+byte_len}), text={repr(text)}")

                replaced[byte_start:byte_start + byte_len] = mask

        return _create_new_ole_file(file_bytes, bytes(replaced))
    except Exception as e:
        print(f"[ERR] 텍스트 치환 중 오류: {e}")
        return file_bytes


# OLE 파일 갱신
def _create_new_ole_file(original_file_bytes: bytes, new_word_data: bytes) -> bytes:
    """기존 OLE 문서의 WordDocument 스트림만 교체"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
            tmp.write(original_file_bytes)
            tmp_path = tmp.name

        with olefile.OleFileIO(tmp_path, write_mode=True) as ole:
            if not ole.exists("WordDocument"):
                return original_file_bytes
            old_len = len(ole.openstream("WordDocument").read())
            if len(new_word_data) != old_len:
                print(f"[WARN] WordDocument 길이 불일치 ({len(new_word_data)} vs {old_len})")
                return original_file_bytes
            ole.write_stream("WordDocument", new_word_data)

        with open(tmp_path, "rb") as f:
            result = f.read()
        os.remove(tmp_path)
        return result
    except Exception as e:
        print(f"[ERR] OLE 교체 중 오류: {e}")
        return original_file_bytes

        
# 전체 레닥션 프로세스
def redact(file_bytes: bytes) -> bytes:
    """DOC 파일 전체 레닥션"""
    try:
        data = extract_text(file_bytes)
        raw_text = data.get("raw_text", "")
        if not raw_text:
            print("[WARN] 추출된 텍스트 없음 → 건너뜀")
            return file_bytes

        norm_text, index_map = normalization_index(raw_text)
        matches = find_sensitive_spans(norm_text)

        # 헤더/바닥글 경계(\r\r, \n\n) 넘는 매치는 분리
        matches = _split_cross_paragraph_matches(matches, norm_text)

        if not matches:
            print("[INFO] 민감정보 없음 → 원본 반환")
            return file_bytes

        targets = []
        for s, e, val, _ in matches:
            if s not in index_map or (e - 1) not in index_map:
                if DEBUG:
                    print(f"[WARN] index_map 누락: {val}")
                continue
            start = index_map[s]
            end = index_map.get(e - 1, start) + 1
            if end <= start:
                end = start + (e - s)
            targets.append((start, end, val))

        return replace_text(file_bytes, targets)
    except Exception as e:
        print(f"[ERR] DOC 레닥션 중 예외: {e}")
        return file_bytes
