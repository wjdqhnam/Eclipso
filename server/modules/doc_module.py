import io
import struct
import olefile
from server.core.redaction_rules import apply_redaction_rules

def _extract_plcpcd(clx: bytes) -> bytes:
    i = 0
    while i < len(clx):
        tag = clx[i]
        i += 1
        if tag == 0x01:  # Prc (서식 정보)
            if i + 2 > len(clx):
                break
            cb = struct.unpack_from("<H", clx, i)[0]
            i += 2 + cb
        elif tag == 0x02:  # Pcdt(PlcPcd)
            if i + 4 > len(clx):
                break
            lcb = struct.unpack_from("<I", clx, i)[0]
            i += 4
            return clx[i:i + lcb]
        else:
            break
    return b""


def _parse_plcpcd(plcpcd: bytes):
    size = len(plcpcd)
    if size < 4 or (size - 4) % 12 != 0:
        return []

    n = (size - 4) // 12
    aCp = [struct.unpack_from("<I", plcpcd, 4 * i)[0] for i in range(n + 1)]
    pcd_off = 4 * (n + 1)
    pieces = []
    for k in range(n):
        pcd_bytes = plcpcd[pcd_off + 8 * k:pcd_off + 8 * (k + 1)]
        fc_raw = struct.unpack_from("<I", pcd_bytes, 2)[0]

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
    try:
        if fCompressed:
            return chunk.decode("cp1252", errors="ignore")
        else:
            return chunk.decode("utf-16le", errors="ignore")
    except Exception:
        return ""


def extract_text(file_bytes: bytes) -> dict:
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("WordDocument"):
                print("WordDocument 스트림 없음 → 빈 텍스트 반환")
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            word_data = ole.openstream("WordDocument").read()
            fib_flags = struct.unpack_from("<H", word_data, 0x000A)[0]
            fWhichTblStm = (fib_flags & 0x0200) != 0
            tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"

            if not ole.exists(tbl_name):
                print("Table 스트림 없음:", tbl_name)
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            table_data = ole.openstream(tbl_name).read()
            fcClx = struct.unpack_from("<I", word_data, 0x01A2)[0]
            lcbClx = struct.unpack_from("<I", word_data, 0x01A6)[0]

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

def redact(file_bytes: bytes) -> bytes:
    """DOC 포맷 유지형 레닥션"""
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("WordDocument"):
            return file_bytes

        word_data = bytearray(ole.openstream("WordDocument").read())
        fib_flags = struct.unpack_from("<H", word_data, 0x000A)[0]
        fWhichTblStm = (fib_flags & 0x0200) != 0
        tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"

        if not ole.exists(tbl_name):
            return file_bytes

        table_data = ole.openstream(tbl_name).read()
        fcClx = struct.unpack_from("<I", word_data, 0x01A2)[0]
        lcbClx = struct.unpack_from("<I", word_data, 0x01A6)[0]

        # 단순하게 전체 텍스트 chunk 순회
        for i in range(0, len(word_data) - 512, 512):
            chunk = word_data[i:i + 512]
            try:
                txt = chunk.decode("utf-16le", errors="ignore")
                red = apply_redaction_rules(txt)
                enc = red.encode("utf-16le")
                word_data[i:i + len(enc)] = enc[:len(chunk)].ljust(len(chunk), b"\x00")
            except Exception:
                continue

        return bytes(word_data)