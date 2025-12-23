import io, os, struct, tempfile, olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.normalize import normalization_index
from server.core.matching import find_sensitive_spans


SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD
HEADER = 0x0014
FOOTER = 0x0015
HEADERFOOTER = 0x089C


def le16(b, off=0): return struct.unpack_from("<H", b, off)[0]
def le32(b, off=0): return struct.unpack_from("<I", b, off)[0]


def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        header_off = off
        off += 4
        payload = data[off:off + length]
        off += length
        yield opcode, length, payload, header_off


# ───────────────────────────────────────────────
# 본문 SST + CONTINUE 부분
# ───────────────────────────────────────────────
def get_sst_blocks(wb: bytes) -> Optional[List[Tuple[bytes, int]]]:
    blocks: List[Tuple[bytes, int]] = []
    found = False
    for opcode, length, payload, hdr in iter_biff_records(wb):
        if opcode == SST:
            blocks.append((payload, hdr + 4))
            found = True
        elif found:
            if opcode == CONTINUE:
                blocks.append((payload, hdr + 4))
            else:
                break
    return blocks if blocks else None

class XLUCSString:
    def __init__(self):
        self.cch = 0
        self.fHigh = 0
        self.fRichSt = 0
        self.fExtSt = 0

        self.cRun = 0
        self.cbExt = 0

        self.text = ""

        self.byte_positions: list[int] = []

class SSTParser:
    def __init__(self, blocks: List[Tuple[bytes, int]]):
        self.blocks = blocks
        self.idx = 0      # 현재 어느 페이로드 블록인지
        self.pos = 0      # 해당 블록 내 현재 오프셋
        self.cur_abs = blocks[0][1]     # Workbook 절대 오프셋 기준 현재 오프셋
        self.reading_text = False       # 문자열 읽는 중인지 여부

    def cur_block(self):
        if self.idx >= len(self.blocks):
            raise EOFError("SST 블록이 소진됨")
        return self.blocks[self.idx]
    
    def next_block(self):
        self.idx += 1
        if self.idx >= len(self.blocks):
            raise EOFError("SST 블록이 소진됨")
        
        payload, abs_off = self.blocks[self.idx]
        self.pos = 0
        self.cur_abs = abs_off

        # 문자열이 CONTINUE로 이어질때만 인코딩 바이트 소비
        if self.reading_text and len(payload) > 0:
            self.pos = 1
            self.cur_abs += 1

    def read_n(self, n: int) -> bytes:
        out = bytearray()
        remain = n

        while remain > 0:
            payload, abs_off = self.cur_block()
            avail = len(payload) - self.pos

            if avail <= 0:
                self.next_block()
                continue

            take = min(avail, remain)
            chunk = payload[self.pos:self.pos + take]
            out.extend(chunk)

            self.pos += take
            self.cur_abs += take
            remain -= take

        return bytes(out)

    def read_str_bytes(self, cch: int, char_size: int):
        self.reading_text = True 
        total = cch * char_size
        out = bytearray()
        pos_list: List[int] = []

        while len(out) < total:
            payload, abs_off = self.cur_block()
            avail = len(payload) - self.pos

            if avail <= 0:
                self.next_block()
                continue

            remain = total - len(out)
            take = min(remain, avail)

            start_abs = self.cur_abs
            chunk = payload[self.pos:self.pos + take]
            out.extend(chunk)

            for i in range(take):
                pos_list.append(start_abs + i)

            self.pos += take
            self.cur_abs += take

        self.reading_text = False
        return bytes(out), pos_list


    def parse_exlucs(self) -> XLUCSString:
        x = XLUCSString()

        x.cch = le16(self.read_n(2))
        flags = self.read_n(1)[0]

        x.fHigh = flags & 0x01
        x.fExtSt = 1 if (flags & 0x04) else 0
        x.fRichSt = 1 if (flags & 0x08) else 0

        if x.fRichSt:
            x.cRun = le16(self.read_n(2))
        if x.fExtSt:
            x.cbExt = le32(self.read_n(4))

        char_size = 2 if x.fHigh else 1

        text_bytes, positions = self.read_str_bytes(x.cch, char_size)
        x.byte_positions = positions

        if x.fHigh:
            x.text = text_bytes.decode("utf-16le", errors="ignore")
        else:
            x.text = text_bytes.decode("latin1", errors="ignore")

        if x.fRichSt and x.cRun > 0:
            self.read_n(4 * x.cRun)

        if x.fExtSt and x.cbExt > 0:
            self.read_n(x.cbExt)

        return x


    def parse(self) -> List[XLUCSString]:
        self.read_n(8)   # SST 헤더 스킵 (cstTotal, cstUnique)
        out = []
        while True:
            try:
                out.append(self.parse_exlucs())
            except EOFError:
                break
        return out



# 문자열 추출
def extract_sst(wb: bytes, strings: List[str]) -> List[str]:
    texts = []

    for opcode, length, payload, hdr in iter_biff_records(wb):
        if opcode == LABELSST:
            idx = le32(payload, 6)
            if 0 <= idx < len(strings):
                texts.append(strings[idx])
    return texts



def encode_masked_text(text: str, fHigh: int) -> bytes:
    char_size = 2 if fHigh else 1
    out = bytearray()

    for ch in text:
        if fHigh:
            encoded = ch.encode("utf-16le", errors="ignore")
        else:
            encoded = ch.encode("latin1", errors="ignore")

        if len(encoded) != char_size:
            raise ValueError("문자 인코딩 길이가 char_size와 일치하지 않음")

        out.extend(encoded)

    return bytes(out)



def parse_xlucs(payload: bytes, off: int):
    start = off

    if off + 3 > len(payload):
        return "", 0, 0, off, 0  # text, cch, fHigh, next offset, raw_len
    
    cch = le16(payload, off)
    fHigh = payload[off + 2] & 0x01
    rgb_off = off + 3

    if fHigh:
        rgb_len = cch * 2
        raw = payload[rgb_off: rgb_off + rgb_len]
        text = raw.decode("utf-16le", errors="ignore")
    else:
        rgb_len = cch
        raw = payload[rgb_off: rgb_off + rgb_len]
        text = raw.decode("latin1", errors="ignore")

    next_off = rgb_off + rgb_len
    raw_len = next_off - start 

    return text, cch, fHigh, next_off, raw_len



def extract_headerfooter(payload: bytes, count=6):
    items = []

    off = 0

    off += 28 # frtHeader, guidSView

    # flags
    flags = le16(payload, off)
    off += 2
    fDiffOddEven = flags & 0x0001
    fDiffFirst   = (flags >> 1) & 0x0001
    print(f"[DEBUG] fDiffOddEven={fDiffOddEven}, fDiffFirst={fDiffFirst}")

    # cchHeaderEven / FooterEven / HeaderFirst / FooterFirst (4 * 2)
    cchHeaderEven  = le16(payload, off); off += 2
    cchFooterEven  = le16(payload, off); off += 2
    cchHeaderFirst = le16(payload, off); off += 2
    cchFooterFirst = le16(payload, off); off += 2

    # str 부분
    for _ in range(count):
        if off >= len(payload):
            break

        text, cch, fHigh, next_off, raw_len = parse_xlucs(payload, off)

        items.append({
            "text": text,
            "cch": cch,
            "fHigh": fHigh,
            "off": off,
            "raw_len": raw_len
        })

        off = next_off

    return items



def extract_text(file_bytes: bytes):
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("Workbook"):
                return {
                    "full_text": "",
                    "pages": [{"page": 1, "text": ""}]
                }

            wb = ole.openstream("Workbook").read()

        # SST 문자열 리스트 만들기
        blocks = get_sst_blocks(wb)
        if blocks:
            xlucs_list = SSTParser(blocks).parse()
            strings = [x.text for x in xlucs_list]
        else:
            strings = []

        # 본문 텍스트
        body = extract_sst(wb, strings)

        header_texts = []

        for opcode, length, payload, hdr in iter_biff_records(wb):

            # HEADER / FOOTER
            if opcode in (HEADER, FOOTER):
                text, cch, fHigh, next_off, raw_len = parse_xlucs(payload, 0)
                if text:
                    header_texts.append(text)

            # HEADERFOOTER
            elif opcode == HEADERFOOTER:
                items = extract_headerfooter(payload)
                for item in items:
                    if item["text"]:
                        header_texts.append(item["text"])

        # 전체 합치기
        combined_texts = body + header_texts
        full_text = "\n".join(combined_texts)

        return {
            "body": body,
            "header_footer": header_texts,
            "full_text": full_text,
            "pages": [{"page": 1, "text": full_text}],
        }

    except Exception as e:
        print("[ERROR extract]:", e)
        return {"full_text": "", "pages": [{"page": 1, "text": ""}]}




def mask_except_hypen(orig_segment: str) -> str:
    out_chars = []
    for ch in orig_segment:
        if ch == "-":
            out_chars.append("-")
        else:
            out_chars.append("*")
    return "".join(out_chars)



def redact_xlucs(text: str) -> str:
    if not text:
        return text

    # 정규화 + 인덱스 매핑
    norm_text, index_map = normalization_index(text)

    # 정규화된 텍스트 기준 매칭
    spans = find_sensitive_spans(norm_text)
    if not spans:
        return text

    chars = list(text)

    # 겹침 방지 - start 기준 역순
    spans = sorted(spans, key=lambda x: x[0], reverse=True)

    for s_norm, e_norm, value, rule in spans:
        # 정규화 인덱스를 원본 인덱스로 역매핑
        s = index_map.get(s_norm)
        e = index_map.get(e_norm - 1)
        if s is None or e is None:
            continue
        e = e + 1  # inclusive → exclusive

        original_seg = text[s:e]
        masked_seg = mask_except_hypen(original_seg)

        # 길이 동일 보장
        if len(masked_seg) != len(original_seg):
            raise ValueError("마스킹 후 길이 불일치")

        # 적용
        for i, ch in enumerate(masked_seg):
            chars[s + i] = ch

    return "".join(chars)


def redact_hdr_fdr(wb: bytearray) -> None:
    for opcode, length, payload, hdr in iter_biff_records(wb):
        # HEADER / FOOTER
        if opcode in (HEADER, FOOTER):
            text, cch, fHigh, next_off, raw_len = parse_xlucs(payload, 0)

            if not text:
                continue

            new_text = redact_xlucs(text)

            if len(new_text) != len(text):
                raise ValueError("Header/Footer 레닥션 길이 불일치")

            raw = encode_masked_text(new_text, fHigh)

            # XLUCS 데이터 시작 offset = record header 4B + XLUCS header 3B
            rgb_start = hdr + 4 + 3

            wb[rgb_start : rgb_start + len(raw)] = raw

        # HEADERFOOTER
        elif opcode == HEADERFOOTER:
            items = extract_headerfooter(payload)

            base = hdr + 4  # payload 시작 위치 (opcode + length)

            for item in items:
                text = item["text"]
                off  = item["off"]      # XLUCS 시작(cch 위치)
                fHigh = item["fHigh"]

                if not text:
                    continue

                new_text = redact_xlucs(text)

                if len(new_text) != len(text):
                    raise ValueError("HEADERFOOTER 레닥션 길이 불일치")

                raw = encode_masked_text(new_text, fHigh)  # 텍스트 바이트만

                # 텍스트 시작 위치: cch(2B) + flags(1B)
                text_start = base + off + 3
                text_end   = text_start + len(raw)

                wb[text_start:text_end] = raw




#OLE 파일 교체
def overlay_workbook_stream(file_bytes: bytes, orig_wb: bytes, new_wb: bytes) -> bytes:
    full = bytearray(file_bytes)

    # workbook 스트림의 위치를 전체 OLE 파일에서 찾음
    pos = full.find(orig_wb)
    if pos == -1:
        print("[WARN] workbook 스트림을 전체 파일에서 찾기 실패")
        return file_bytes
    
    # 길이 바뀌면 Error
    if len(orig_wb) != len(new_wb):
        raise ValueError(
            "[ERROR ! !] 동일길이 치환 실패"
            f"original = {len(orig_wb)}, new = {len(new_wb)}"
        )
    
    # 전체 파일 내 workbook 영역 교체
    full[pos : pos + len(orig_wb)] = new_wb

    return bytes(full)


def redact(file_bytes: bytes) -> bytes:
    print("[INFO] XLS Redaction 시작")

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("Workbook"):
            print("[ERROR] Workbook 없음")
            return file_bytes
        orig_wb = ole.openstream("Workbook").read()

    wb = bytearray(orig_wb)

    # SST 레닥션
    blocks = get_sst_blocks(wb)
    if not blocks:
        return file_bytes

    xlucs_list = SSTParser(blocks).parse()

    for x in xlucs_list:
        red_text = redact_xlucs(x.text)

        # 문자 수 동일해야 함
        if len(red_text) != len(x.text):
            raise ValueError("동일길이 레닥션 실패 (문자 수 불일치)")

        # fHigh 기반 인코딩
        raw = encode_masked_text(red_text, x.fHigh)

        # byte_positions와 길이 동일해야 함
        if len(raw) != len(x.byte_positions):
            raise ValueError("raw 길이 mismatch")

        # CONTINUE-aware 바이트 패치
        for i, pos in enumerate(x.byte_positions):
            wb[pos] = raw[i]
    print("[OK] SST 텍스트 레닥션 완료")
    
    # 헤더/바닥글 레닥션
    redact_hdr_fdr(wb)
    print("[OK] 헤더/푸터 텍스트 레닥션 완료")

    return overlay_workbook_stream(file_bytes, orig_wb, bytes(wb))

