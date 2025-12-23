import io, os, struct, tempfile, olefile
from typing import Optional, List, Tuple

from server.core.normalize import normalization_text
from server.core.matching import find_sensitive_spans


def le16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]


# BIFF 레코드 반복자
def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        off += 4
        payload = data[off : off + length]
        yield off - 4, opcode, length, payload
        off += length


# ShortXLUnicodeString
def parse_short_xlucs(buf: bytes, off: int, single_byte_codec: str):
    if off + 2 > len(buf):
        raise ValueError("ShortXLUnicodeString header가 잘렸습니다.")

    cch = buf[off]
    flags = buf[off + 1]
    fHigh = flags & 0x01

    if fHigh:
        byte_len = cch * 2
        start = off + 2
        end = start + byte_len
        if end > len(buf):
            raise ValueError("ShortXLUnicodeString UTF-16 payload가 잘렸습니다.")
        raw = buf[start:end]
        text = raw.decode("utf-16le", errors="ignore")
    else:
        byte_len = cch
        start = off + 2
        end = start + byte_len
        if end > len(buf):
            raise ValueError("ShortXLUnicodeString single-byte payload가 잘렸습니다.")
        raw = buf[start:end]
        text = raw.decode(single_byte_codec, errors="ignore")

    return text, cch, fHigh, 2 + byte_len


def build_short_xlucs(text: str, cch: int, fHigh: int, single_byte_codec: str) -> bytes:
    if len(text) != cch:
        # 길이 불일치면 BIFF 구조 깨질 수 있으니 안전하게 예외
        raise ValueError("ShortXLUnicodeString 길이(cch)와 text 길이가 일치하지 않습니다.")

    flags = fHigh & 0x01
    if fHigh:
        rgb = text.encode("utf-16le")
    else:
        rgb = text.encode(single_byte_codec, errors="ignore")

    return bytes([cch, flags]) + rgb


# ─────────────────────────────
# SeriesText 추출 / 레닥션
# ─────────────────────────────
SERIESTEXT_OPCODE = 0x100D  # SeriesText
FRTWRAPPER_RT = 0x0851      # (여기서는 미사용) FrtWrapper.frtHeaderOld.rt 값


def extract_seriesTexts(biff_bytes: bytes, single_byte_codec="cp949") -> List[str]:
    wb = biff_bytes
    texts: List[str] = []

    for rec_off, opcode, length, payload in iter_biff_records(wb):
        # SeriesText(0x100D) 단독 레코드만 처리
        if opcode != SERIESTEXT_OPCODE:
            continue
        if length < 4:  # reserved(2) + 최소 payload
            continue

        series_payload_off = rec_off + 4  # reserved가 시작하는 곳
        reserved_off = series_payload_off

        # reserved = 2 bytes
        st_off = reserved_off + 2  # stText 시작 오프셋

        try:
            text, cch, fHigh, used = parse_short_xlucs(wb, st_off, single_byte_codec)
        except Exception:
            continue

        if text and text.strip():
            texts.append(text.strip())

    return texts


def redact_seriesTexts(biff_bytes: bytes, single_byte_codec="cp949") -> bytes:
    wb = bytearray(biff_bytes)
    red_total = 0

    for rec_off, opcode, length, payload in iter_biff_records(wb):
        # SeriesText 단독 레코드만 처리
        if opcode != SERIESTEXT_OPCODE:
            continue
        if length < 4:
            continue

        payload_off = rec_off + 4   # reserved(2 bytes) 시작
        st_off = payload_off + 2    # stText 시작

        try:
            text, cch, fHigh, used = parse_short_xlucs(wb, st_off, single_byte_codec)
        except Exception:
            continue

        if not text:
            continue

        norm = normalization_text(text)
        if not find_sensitive_spans(norm):
            continue

        print(f"[CHART - SERIES] SeriesText 매칭됨: {repr(text)} at 0x{st_off:08X}")

        masked_text = "*" * len(text)
        try:
            new_st = build_short_xlucs(masked_text, cch, fHigh, single_byte_codec)
        except Exception:
            continue

        record_payload_start = rec_off + 4
        record_payload_end = record_payload_start + length

        # ShortXLUnicodeString은 reserved 뒤에 붙는 부분
        if st_off + len(new_st) > record_payload_end:
            # masked string이 record payload를 초과하면 BIFF 구조 깨짐
            continue

        # record payload 내에서만 덮어쓰기
        wb[st_off : st_off + len(new_st)] = new_st
        red_total += 1

    if red_total:
        print(f"[CHART - SERIES] 총 {red_total} SeriesText string이 레닥션 됨.")
    else:
        print("[CHART - SERIES] SeriesText 레닥션 안된다.")

    return bytes(wb)


# 차트 텍스트 추출
def extract_chart_text(file_bytes: bytes, single_byte_enc: str = "cp949") -> List[str]:
    texts: List[str] = []

    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            for entry in ole.listdir():
                if len(entry) < 2:
                    continue

                top = entry[0]
                name = entry[-1]

                if top == "ObjectPool" and name in ("Workbook", "\x01Workbook"):
                    wb_data = ole.openstream(entry).read()
                    texts.extend(extract_seriesTexts(wb_data, single_byte_enc))

                # EPRINT는 여기서는 추출 안 함
    except Exception as e:
        print(f"[ERR] extract_chart_text: {e}")

    return texts


# ───────────────────────────────────────────────
# EPRINT (EMF) 레닥션
# ───────────────────────────────────────────────
EMR_EXTTEXTOUTA = 0x53
EMR_EXTTEXTOUTW = 0x54
EMR_POLYTEXTOUTA = 0x60
EMR_POLYTEXTOUTW = 0x61
EMR_SMALLTEXTOUT = 0x6C


def iter_emf_records(data: bytearray):
    off = 0
    n = len(data)

    while off + 8 <= n:
        rec_type = le32(data, off)
        rec_size = le32(data, off + 4)

        if rec_size <= 0 or off + rec_size > n:
            break

        payload_off = off + 8
        payload = data[payload_off : off + rec_size]

        yield off, rec_type, rec_size, payload
        off += rec_size


def parse_emr_polytextout(emf: bytearray, rec_off: int, rec_size: int, is_unicode: bool):
    base = rec_off

    size = le32(emf, base + 4)
    if size != rec_size:
        return []

    pos = base + 8

    # Bounds RECT
    pos += 16

    # iGraphicsMode(4), exScale(4), eyScale(4)
    pos += 12

    cStrings = le32(emf, pos)
    pos += 4

    segments = []
    ETO_NO_RECT = 0x100

    for _ in range(cStrings):
        pos += 8  # POINTL

        chars = le32(emf, pos); pos += 4
        offString = le32(emf, pos); pos += 4
        options = le32(emf, pos); pos += 4

        if not (options & ETO_NO_RECT):
            pos += 16

        pos += 4  # offDx

        if chars == 0 or offString == 0:
            continue

        if is_unicode:
            bpc = 2
            encoding = "utf-16le"
        else:
            bpc = 1
            encoding = "cp949"

        str_start = base + offString
        str_len = chars * bpc
        str_end = str_start + str_len

        if not (base <= str_start < str_end <= base + rec_size):
            continue

        segments.append((str_start, str_len, encoding))

    return segments


def parse_emr_smalltextout(emf: bytearray, rec_off: int, rec_size: int):
    base = rec_off

    rec_type = le32(emf, base)
    size = le32(emf, base + 4)

    if rec_type != EMR_SMALLTEXTOUT or size != rec_size:
        return None

    pos = base + 8

    # x, y
    pos += 8

    cChars = le32(emf, pos); pos += 4
    fuOptions = le32(emf, pos); pos += 4

    # iGraphicsMode
    pos += 4

    # exScale, eyScale
    pos += 8

    ETO_NO_RECT = 0x100
    ETO_SMALL_CHARS = 0x8000

    if not (fuOptions & ETO_NO_RECT):
        pos += 16

    text_start = pos

    if fuOptions & ETO_SMALL_CHARS:
        byte_len = cChars
        encoding = "cp949"
    else:
        byte_len = cChars * 2
        encoding = "utf-16le"

    if text_start + byte_len > base + rec_size:
        return None

    return (text_start, byte_len, encoding)


def redact_emr_block(emf: bytearray, rec_off: int, is_unicode: bool) -> int:
    rec_size = le32(emf, rec_off + 4)

    emrtext_off = rec_off + 0x24
    if emrtext_off + 16 > rec_off + rec_size:
        return 0

    chars = le32(emf, emrtext_off + 8)
    off_string = le32(emf, emrtext_off + 12)

    if chars == 0 or off_string == 0:
        return 0

    str_start = rec_off + off_string
    bpc = 2 if is_unicode else 1
    str_bytes_len = chars * bpc
    str_end = str_start + str_bytes_len

    rec_end = rec_off + rec_size
    if str_end > rec_end:
        return 0

    raw = bytes(emf[str_start:str_end])
    enc = "utf-16le" if is_unicode else "cp949"

    try:
        text = raw.decode(enc, errors="ignore")
    except Exception:
        return 0

    if not find_sensitive_spans(normalization_text(text)):
        return 0

    redacted = ("*" * len(text)).encode(enc)
    redacted = redacted[:len(raw)].ljust(len(raw), b"*")

    emf[str_start:str_end] = redacted
    print(f"[EMR] redacted text: {repr(text)} at 0x{str_start:08X}")

    return 1


def redact_emf_stream(emf_bytes: bytes) -> bytes:
    emf = bytearray(emf_bytes)
    total = 0

    for rec_off, rec_type, rec_size, payload in iter_emf_records(emf):
        if rec_type == EMR_EXTTEXTOUTA:
            total += redact_emr_block(emf, rec_off, False)

        elif rec_type == EMR_EXTTEXTOUTW:
            total += redact_emr_block(emf, rec_off, True)

        elif rec_type in (EMR_POLYTEXTOUTA, EMR_POLYTEXTOUTW):
            is_unicode = (rec_type == EMR_POLYTEXTOUTW)
            segs = parse_emr_polytextout(emf, rec_off, rec_size, is_unicode)

            for start, length, enc in segs:
                raw = bytes(emf[start : start + length])
                try:
                    text = raw.decode(enc, errors="ignore")
                except Exception:
                    continue

                if find_sensitive_spans(normalization_text(text)):
                    red = ("*" * len(text)).encode(enc)
                    red = red[:length].ljust(length, b"*")
                    emf[start : start + length] = red
                    total += 1
                    print(f"[EMR-POLY] redacted {repr(text)} at 0x{start:08X}")

        elif rec_type == EMR_SMALLTEXTOUT:
            seg = parse_emr_smalltextout(emf, rec_off, rec_size)
            if seg:
                start, length, enc = seg
                raw = bytes(emf[start : start + length])
                try:
                    text = raw.decode(enc, errors="ignore")
                except Exception:
                    continue

                if find_sensitive_spans(normalization_text(text)):
                    red = ("*" * len(text)).encode(enc)
                    red = red[:length].ljust(length, b"*")
                    emf[start : start + length] = red
                    total += 1
                    print(f"[EMR-SMALL] redacted {repr(text)} at 0x{start:08X}")

    if total:
        print(f"[EMR OK] total {total} text(s) redacted in EMF")
    else:
        print("[EMR ERR] no redactions in EMF")

    return bytes(emf)


# ───────────────────────────────────────────────
# 차트 부분 전체 처리
# ───────────────────────────────────────────────
def redact_workbooks(file_bytes: bytes, single_byte_codec: str = "cp949") -> bytes:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
        tmp.write(file_bytes)
        temp_path = tmp.name

    try:
        # olefile이 write_mode=True 및 write_stream(entry, data)를 지원하는 환경을 전제로 함
        with olefile.OleFileIO(temp_path, write_mode=True) as ole:
            entries = ole.listdir()

            for entry in entries:
                if len(entry) < 2:
                    continue

                top = entry[0]
                name = entry[-1]

                # Workbook 레닥션
                if top == "ObjectPool" and name in ("Workbook", "\x01Workbook"):
                    print(f"[INFO] redact Workbook: {'/'.join(entry)}")

                    wb_data = ole.openstream(entry).read()
                    new_biff = redact_seriesTexts(wb_data, single_byte_codec)

                    if new_biff != wb_data:
                        ole.write_stream(entry, new_biff)
                        print(f"  [WRITE] Workbook updated: {'/'.join(entry)}")
                    else:
                        print("  [SKIP] Workbook unchanged")

                # EPRINT 레닥션
                if top == "ObjectPool" and name == "\x03EPRINT":
                    print(f"[INFO] redact EPRINT: {'/'.join(entry)}")

                    emf_data = ole.openstream(entry).read()
                    new_emf = redact_emf_stream(emf_data)

                    if new_emf != emf_data:
                        ole.write_stream(entry, new_emf)
                        print(f"  [WRITE] EPRINT updated: {'/'.join(entry)}")
                    else:
                        print("  [SKIP] EPRINT unchanged")

        with open(temp_path, "rb") as f:
            return f.read()

    except Exception as e:
        print(f"[ERR] redact_workbooks exception: {e}")
        # 실패 시 원본 그대로 반환
        return file_bytes

    finally:
        # temp 파일 정리 (충돌 마커 제거)
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
