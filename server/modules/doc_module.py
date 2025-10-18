import io
import struct
import olefile
from server.core.redaction_rules import apply_redaction_rules
from typing import List, Dict, Any


def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


# CLX / PlcPcd 관련 파서
def _extract_plcpcd(clx: bytes) -> bytes:
    """CLX 블록에서 PlcPcd 서브블록 추출"""
    i = 0
    while i < len(clx):
        tag = clx[i]
        i += 1
        if tag == 0x01:  # Prc (서식 정보)
            if i + 2 > len(clx): break
            cb = struct.unpack_from("<H", clx, i)[0]
            i += 2 + cb
        elif tag == 0x02:  # Pcdt (PlcPcd)
            if i + 4 > len(clx): break
            lcb = struct.unpack_from("<I", clx, i)[0]
            i += 4
            return clx[i:i + lcb]
        else:
            break
    return b""


def _parse_plcpcd(plcpcd: bytes) -> List[Dict[str, Any]]:
    """PlcPcd에서 조각 정보 추출"""
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

        cp_start = aCp[k]
        cp_end = aCp[k + 1]
        char_count = cp_end - cp_start
        byte_count = char_count if fCompressed else char_count * 2

        pieces.append({
            "index": k,
            "fc": fc,
            "byte_count": byte_count,
            "fCompressed": fCompressed
        })
    return pieces


def _decode_piece(chunk: bytes, fCompressed: bool) -> str:
    """조각 디코딩"""
    try:
        if fCompressed:
            return chunk.decode("cp1252", errors="ignore")
        else:
            return chunk.decode("utf-16le", errors="ignore")
    except Exception:
        return ""



# 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
    """DOC 본문 텍스트 추출"""
    try:
        buffer = io.BytesIO(file_bytes)
        buffer.seek(0)

        with olefile.OleFileIO(buffer) as ole:
            if not ole.exists("WordDocument"):
                print("WordDocument 스트림 없음 → 빈 텍스트 반환")
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            word_data = ole.openstream("WordDocument").read()
            fib_flags = le16(word_data, 0x000A)
            fWhichTblStm = (fib_flags & 0x0200) != 0
            tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"

            if not ole.exists(tbl_name):
                print("Table 스트림 없음:", tbl_name)
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            table_data = ole.openstream(tbl_name).read()
            fcClx = le32(word_data, 0x01A2)
            lcbClx = le32(word_data, 0x01A6)

            if fcClx + lcbClx > len(table_data):
                print("CLX 범위 초과 → 무시")
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            clx = table_data[fcClx:fcClx + lcbClx]
            plcpcd = _extract_plcpcd(clx)
            if not plcpcd:
                print("PlcPcd 없음")
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            pieces = _parse_plcpcd(plcpcd)
            texts = []
            for p in pieces[:5]:
                start, end = p["fc"], p["fc"] + p["byte_count"]
                if end > len(word_data):
                    continue
                chunk = word_data[start:end]
                texts.append(_decode_piece(chunk, p["fCompressed"]))

            full_text = "\n".join(texts)
            return {"full_text": full_text, "pages": [{"page": 1, "text": full_text}]}

    except Exception as e:
        print("DOC 추출 중 예외:", e)
        return {"full_text": "", "pages": [{"page": 1, "text": ""}]}




# DOC 포맷 유지형 레닥션 (파일 구조 보존)
def redact(file_bytes: bytes) -> bytes:
    """DOC 포맷 유지하면서 레닥션"""
    try:
        print("DOC DEBUG HEADER:", file_bytes[:32].hex().upper())
        print("파일 전체 크기:", len(file_bytes))

        # 헤더 검사
        if not file_bytes.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            print("[ERROR] Doc 파일이 아닙니다.")
            return file_bytes

        buffer = io.BytesIO(file_bytes)
        buffer.seek(0)

        with olefile.OleFileIO(buffer) as ole:
            if not ole.exists("WordDocument"):
                print("WordDocument 스트림 없음")
                return file_bytes

            # WordDocument 스트림 수정
            word_data = bytearray(ole.openstream("WordDocument").read())

            # 단순 텍스트 블록 단위 레닥션
            for i in range(0, len(word_data), 512):
                chunk = word_data[i:i + 512]
                try:
                    txt = chunk.decode("utf-16le", errors="ignore")
                    red = apply_redaction_rules(txt)
                    enc = red.encode("utf-16le")
                    word_data[i:i + len(enc)] = enc[:len(chunk)].ljust(len(chunk), b"\x00")
                except Exception:
                    continue

            print("[OK] WordDocument 수정 완료")
            return bytes(word_data)

    except Exception as e:
        print(f"DOC 기본 레닥션 중 오류: {e}")
        return file_bytes



# 특정 문자열 동일 길이 치환
def replace_text(file_bytes: bytes, targets: List[str], replacement_char: str = "*") -> bytes:
    """DOC 파일에서 특정 문자열을 동일 길이로 치환"""
    try:
        buffer = io.BytesIO(file_bytes)
        buffer.seek(0)

        with olefile.OleFileIO(buffer) as ole:
            if not ole.exists("WordDocument"):
                return file_bytes

            word_data = ole.openstream("WordDocument").read()
            fib_flags = le16(word_data, 0x000A)
            fWhichTblStm = (fib_flags & 0x0200) != 0
            tbl_stream = "1Table" if fWhichTblStm else "0Table"

            if not ole.exists(tbl_stream):
                return file_bytes

            table_data = ole.openstream(tbl_stream).read()
            fcClx = le32(word_data, 0x01A2)
            lcbClx = le32(word_data, 0x01A6)

            if lcbClx == 0 or fcClx + lcbClx > len(table_data):
                return file_bytes

            clx = table_data[fcClx:fcClx + lcbClx]
            plcpcd = _extract_plcpcd(clx)
            pieces = _parse_plcpcd(plcpcd)

            replaced_word_data = bytearray(word_data)
            total_replacement = 0

            for target_text in targets:
                replacement_text = "".join(c if c == "-" else replacement_char for c in target_text)
                for p in pieces:
                    start_pos = p["fc"]
                    end_pos = p["fc"] + p["byte_count"]
                    if end_pos > len(word_data):
                        continue

                    chunk = word_data[start_pos:end_pos]
                    text = _decode_piece(chunk, p["fCompressed"])

                    search_start = 0
                    while True:
                        idx = text.find(target_text, search_start)
                        if idx == -1:
                            break

                        bytes_per_char = 1 if p["fCompressed"] else 2
                        byte_start = start_pos + idx * bytes_per_char
                        byte_len = len(target_text) * bytes_per_char

                        enc = "cp1252" if p["fCompressed"] else "utf-16le"
                        replacement_bytes = replacement_text.encode(enc, errors="replace")

                        if len(replacement_bytes) != byte_len:
                            replacement_bytes = replacement_bytes.ljust(byte_len, b"\x00")

                        replaced_word_data[byte_start:byte_start + byte_len] = replacement_bytes
                        total_replacement += 1
                        search_start = idx + len(target_text)

            print(f"총 {total_replacement}개 치환 완료")
            return bytes(replaced_word_data)

    except Exception as e:
        print(f"DOC 치환 중 오류: {e}")
        return file_bytes



def redact_with_targets(file_bytes: bytes, targets: List[str] = None) -> bytes:
    """target이 없으면 기본 레닥션, 있으면 직접 치환"""
    if not targets:
        return redact(file_bytes)
    else:
        return replace_text(file_bytes, targets)


def validate_doc_file(file_bytes: bytes) -> bool:
    """DOC 파일이 올바른 OLE 컨테이너인지 검증"""
    try:
        buffer = io.BytesIO(file_bytes)
        buffer.seek(0)
        with olefile.OleFileIO(buffer) as ole:
            if not ole.exists("WordDocument"):
                print("WordDocument 스트림 없음")
                return False
            ole.openstream("WordDocument").read()
            print("DOC 파일 검증 성공")
            return True
    except Exception as e:
        print(f"DOC 파일 검증 실패: {e}")
        return False


def get_doc_info(file_bytes: bytes) -> dict:
    """DOC 파일 기본 구조 정보 반환"""
    try:
        buffer = io.BytesIO(file_bytes)
        buffer.seek(0)
        with olefile.OleFileIO(buffer) as ole:
            info = {
                "is_valid_ole": True,
                "streams": ole.listdir(),
                "worddocument_size": 0,
                "has_table_stream": False
            }
            if ole.exists("WordDocument"):
                word_data = ole.openstream("WordDocument").read()
                info["worddocument_size"] = len(word_data)
                fib_flags = le16(word_data, 0x000A)
                fWhichTblStm = (fib_flags & 0x0200) != 0
                tbl_name = "1Table" if fWhichTblStm else "0Table"
                info["has_table_stream"] = ole.exists(tbl_name)
                info["table_stream_name"] = tbl_name
            return info
    except Exception as e:
        return {
            "is_valid_ole": False,
            "error": str(e),
            "streams": [],
            "worddocument_size": 0,
            "has_table_stream": False
        }
