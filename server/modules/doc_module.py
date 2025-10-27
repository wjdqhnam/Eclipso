import io
import struct
import tempfile
import os
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans


def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


# 테이블 스트림 이름 반환
def _get_table_stream_name(word_data: bytes, ole: olefile.OleFileIO) -> Optional[str]:
    fib_flags = le16(word_data, 0x000A)
    fWhichTblStm = (fib_flags & 0x0200) != 0
    tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"
    return tbl_name if ole.exists(tbl_name) else None


# WordDocument와 Table 스트림 읽기
def _read_word_and_table_streams(file_bytes: bytes) -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
    try:
        buffer = io.BytesIO(file_bytes)
        buffer.seek(0)
        with olefile.OleFileIO(buffer) as ole:
            if not ole.exists("WordDocument"):
                return None, None, None
            word_data = ole.openstream("WordDocument").read()
            tbl_name = _get_table_stream_name(word_data, ole)
            if not tbl_name:
                return word_data, None, None
            table_data = ole.openstream(tbl_name).read()
            return word_data, table_data, tbl_name
    except Exception:
        return None, None, None


# CLX 데이터 추출
def _get_clx_data(word_data: bytes, table_data: bytes) -> Optional[bytes]:
    fcClx = le32(word_data, 0x01A2)
    lcbClx = le32(word_data, 0x01A6)
    if fcClx + lcbClx > len(table_data):
        return None
    return table_data[fcClx:fcClx + lcbClx]


# CLX 블록에서 PlcPcd 서브블록 추출
def _extract_plcpcd(clx: bytes) -> bytes:
    i = 0
    while i < len(clx):
        tag = clx[i]
        i += 1
        if tag == 0x01:
            if i + 2 > len(clx): break
            cb = struct.unpack_from("<H", clx, i)[0]
            i += 2 + cb
        elif tag == 0x02:
            if i + 4 > len(clx): break
            lcb = struct.unpack_from("<I", clx, i)[0]
            i += 4
            return clx[i:i + lcb]
        else:
            break
    return b""


# PlcPcd에서 조각 정보 추출
def _parse_plcpcd(plcpcd: bytes) -> List[Dict[str, Any]]:
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
        cp_start = aCp[k]
        cp_end = aCp[k+1]
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


# 조각 디코딩
def _decode_piece(chunk: bytes, fCompressed: bool) -> str:
    try:
        return chunk.decode("cp1252" if fCompressed else "utf-16le", errors="ignore")
    except Exception:
        return ""


# 텍스트 추출 (정규화 포함)
def extract_text(file_bytes: bytes) -> dict:
    pieces: List[Dict[str, Any]] = [] 
    try:
        word_data, table_data, tbl_name = _read_word_and_table_streams(file_bytes)
        if not word_data:
            print("WordDocument 스트림 없음 → 빈 텍스트 반환")
            return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}], "pieces": pieces}
        if not table_data:
            print("Table 스트림 없음:", tbl_name)
            return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}], "pieces": pieces}
        clx = _get_clx_data(word_data, table_data)
        if not clx:
            print("CLX 범위 초과 → 무시")
            return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}], "pieces": pieces}
        plcpcd = _extract_plcpcd(clx)
        if not plcpcd:
            print("PlcPcd 없음")
            return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}], "pieces": pieces}
        pieces = _parse_plcpcd(plcpcd)

        texts = []
        for p in pieces:
            start, end = p["fc"], p["fc"] + p["byte_count"]
            if end > len(word_data): 
                continue
            chunk = word_data[start:end]
            texts.append(_decode_piece(chunk, p["fCompressed"]))

        full_text = "".join(texts)
        normalized_text = normalization_text(full_text)
        return {
            "full_text": normalized_text,
            "raw_text": full_text,
            "pages": [{"page": 1, "text": normalized_text}],
            "pieces": pieces, 
        }
    
    except Exception as e:
        print("DOC 추출 중 예외:", e)
        return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}], "pieces": pieces}



# 동일 길이의 *로 치환 (Piece 단위 cp→fc 변환)
def replace_text(
    file_bytes: bytes,
    targets: List[Tuple[int, int, str]],
    pieces: List[Dict[str, Any]],
    replacement_char: str = "*"
) -> bytes:
    try:
        word_data, table_data, tbl_name = _read_word_and_table_streams(file_bytes)
        if not word_data or not table_data:
            raise ValueError("WordDocument 또는 Table 스트림을 읽을 수 없습니다")

        # 전달받은 pieces로 cp→fc 매핑 구성
        piece_spans = []
        for p in pieces:
            cp_start = p["cp_start"]
            cp_end = p["cp_end"]
            fc_base = p["fc"]
            bpc = 1 if p["fCompressed"] else 2
            piece_spans.append((cp_start, cp_end, fc_base, bpc))

        replaced_word_data = bytearray(word_data)
        total_replacement = 0

        for start, end, _ in targets:
            if start >= end:
                continue
            for text_start, text_end, fc_base, bpc in piece_spans:
                if start >= text_end or end <= text_start:
                    continue
                local_start = max(start, text_start)
                local_end   = min(end, text_end)
                if local_start >= local_end:
                    continue

                byte_start = fc_base + (local_start - text_start) * bpc
                byte_len   = (local_end - local_start) * bpc

                if bpc == 1:
                    unit = (replacement_char.encode("latin-1", "ignore") or b"*")[0:1]
                    replacement_bytes = unit * byte_len
                else:
                    unit = (replacement_char.encode("utf-16le")[:2] or b"*\x00")
                    replacement_bytes = unit * (byte_len // 2)

                replaced_word_data[byte_start:byte_start+byte_len] = replacement_bytes
                total_replacement += 1

        print(f"총 {total_replacement}개 치환 완료")
        return _create_new_ole_file(file_bytes, bytes(replaced_word_data))
    except Exception as e:
        print(f"텍스트 치환 중 오류: {e}")
        return file_bytes



# WordDocument 스트림 교체
def _create_new_ole_file(original_file_bytes: bytes, new_word_data: bytes) -> bytes:
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
            tmp.write(original_file_bytes)
            tmp_path = tmp.name
        with olefile.OleFileIO(tmp_path, write_mode=True) as ole:
            if not ole.exists("WordDocument"):
                print("[WARN] WordDocument 스트림 없음")
                return original_file_bytes
            old_data = ole.openstream("WordDocument").read()
            if len(old_data) != len(new_word_data):
                print(f"[WARN] WordDocument 길이 불일치 → 교체 중단 ({len(new_word_data)} vs {len(old_data)})")
                return original_file_bytes
            ole.write_stream("WordDocument", new_word_data)
            print("[OK] WordDocument 스트림 교체 완료")
        with open(tmp_path, "rb") as f:
            result = f.read()
        os.remove(tmp_path)
        return result
    except Exception as e:
        print(f"OLE 파일 생성 중 오류: {e}")
        return original_file_bytes

# 레닥션
def redact(file_bytes: bytes) -> bytes:
    try:
        extracted_data = extract_text(file_bytes)
        original_text = extracted_data.get("raw_text", extracted_data.get("full_text", ""))
        if not original_text:
            print("추출된 텍스트가 없음. 레닥션 건너뜀")
            return file_bytes

        normalized_text, index_map = normalization_index(original_text)

        matches = find_sensitive_spans(normalized_text)
        if not matches:
            print("민감정보가 발견되지 않아 원본 파일 반환")
            return file_bytes

        targets = []
        for start, end, value, _ in matches:
            # index_map 누락 보호
            if start not in index_map or (end - 1) not in index_map:
                continue
            orig_start = index_map[start]
            orig_end = index_map[end - 1] + 1
            if orig_start < orig_end:
                targets.append((orig_start, orig_end, value))

        pieces = extracted_data.get("pieces", [])
        return replace_text(file_bytes, targets, pieces)

    except Exception as e:
        print(f"DOC 레닥션 중 오류: {e}")
        return file_bytes
