import io, os, struct, tempfile, olefile
from typing import List, Dict, Any, Tuple, Optional, Set

from server.core.normalize import normalization_index
from server.core.matching import find_sensitive_spans


SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD
HEADER = 0x0014
FOOTER = 0x0015
HEADERFOOTER = 0x089C
LABEL = 0x00FD
BOF = 0x0809
EOF = 0x000A
BOUNDSHEET = 0x0085
CODEPAGE = 0x0042
NUMBER = 0x0203
RK = 0x027E
MULRK = 0x00BD
BOOLERR = 0x0205
FORMULA = 0x0006
MSODRAWINGGROUP = 0x00EB
MSODRAWING = 0x00EC
OBJ        = 0x005D
TXO = 0x01B6


def le16(b, off=0) -> int:
    return struct.unpack_from("<H", b, off)[0]


def le32(b, off=0) -> int:
    return struct.unpack_from("<I", b, off)[0]


def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        header_off = off
        off += 4        
        payload = data[off:off + length]
        off += length
        yield opcode, length, payload, header_off


def iter_biff_records_from(data: bytes, start_off: int):
    off, n = int(start_off), len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        header_off = off
        off += 4
        payload = data[off:off + length]
        off += length
        yield opcode, length, payload, header_off


def _escape_html(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _cell_to_html(cell: str) -> str:
    s = (cell or "").replace("\r\n", "\n").replace("\r", "\n")
    return _escape_html(s).replace("\n", "<br/>")


def _rows_to_html_table(rows: List[List[str]]) -> str:
    if not rows:
        return ""
    w = max((len(r) for r in rows), default=0)
    rect = [list(r) + [""] * (w - len(r)) for r in rows]
    out: List[str] = []
    out.append("<table>")
    out.append("<tbody>")
    for r in rect:
        out.append("<tr>")
        for c in r:
            out.append(f"<td>{_cell_to_html(c)}</td>")
        out.append("</tr>")
    out.append("</tbody>")
    out.append("</table>")
    return "\n".join(out)


def _parse_boundsheets(wb: bytes) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for opcode, length, payload, hdr in iter_biff_records(wb):
        if opcode != BOUNDSHEET:
            continue
        if len(payload) < 8:
            continue
        off = le32(payload, 0)
        name_len = payload[6]
        flags = payload[7]
        name_bytes = payload[8:8 + (name_len * (2 if (flags & 0x01) else 1))]
        try:
            if flags & 0x01:
                name = name_bytes.decode("utf-16le", errors="ignore")
            else:
                name = name_bytes.decode("latin1", errors="ignore")
        except Exception:
            name = f"Sheet@{off}"
        out.append((name or f"Sheet@{off}", int(off)))
    return out


def _extract_sheet_grid(wb: bytes, strings: List[str], sheet_off: int, max_rows: int = 200, max_cols: int = 50) -> List[List[str]]:
    cells: Dict[int, Dict[int, str]] = {}
    max_r = 0
    max_c = 0

    for opcode, length, payload, hdr in iter_biff_records_from(wb, sheet_off):
        if opcode == EOF:
            break
        try:
            if opcode == LABELSST and len(payload) >= 10:
                r = le16(payload, 0)
                c = le16(payload, 2)
                sst_idx = le32(payload, 6)
                v = strings[sst_idx] if 0 <= sst_idx < len(strings) else ""
                if v:
                    cells.setdefault(r + 1, {})[c + 1] = v
                    max_r = max(max_r, r + 1)
                    max_c = max(max_c, c + 1)
            elif opcode == NUMBER and len(payload) >= 14:
                r = le16(payload, 0)
                c = le16(payload, 2)
                if r + 1 > max_rows or c + 1 > max_cols:
                    continue
                val = struct.unpack_from("<d", payload, 6)[0]
                v = str(int(val)) if abs(val - int(val)) < 1e-9 else str(val)
                cells.setdefault(r + 1, {})[c + 1] = v
                max_r = max(max_r, r + 1)
                max_c = max(max_c, c + 1)
            elif opcode == LABEL and len(payload) >= 8:
                r = le16(payload, 0)
                c = le16(payload, 2)
                if r + 1 > max_rows or c + 1 > max_cols:
                    continue
                cch = le16(payload, 6)
                raw = payload[8:8 + cch]
                try:
                    v = raw.decode("latin1", errors="ignore")
                except Exception:
                    v = ""
                if v:
                    cells.setdefault(r + 1, {})[c + 1] = v
                    max_r = max(max_r, r + 1)
                    max_c = max(max_c, c + 1)
        except Exception:
            continue

    if not cells:
        return []

    rows: List[List[str]] = []
    for r in range(1, max_r + 1):
        row = [cells.get(r, {}).get(c, "") for c in range(1, max_c + 1)]
        if any(x.strip() for x in row):
            rows.append(row)
    return rows


def extract_markdown_tables_from_xls(file_bytes: bytes) -> str:
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("Workbook"):
                return ""
            wb = ole.openstream("Workbook").read()
    except Exception:
        return ""

    blocks = get_sst_blocks(wb)
    if blocks:
        xlucs_list = SSTParser(blocks).parse()
        strings = [x.text for x in xlucs_list]
    else:
        strings = []

    sheets = _parse_boundsheets(wb)
    if not sheets:
        return ""

    out: List[str] = []
    for name, off in sheets:
        rows = _extract_sheet_grid(wb, strings, off)
        if not rows:
            continue
        out.append(f"**Sheet: {_escape_html(name)}**")
        out.append(_rows_to_html_table(rows))
        out.append("")
    return "\n\n".join(out).strip()

# 본문 SST + CONTINUE 부분
def get_sst_blocks(wb: bytes) -> Optional[List[Tuple[bytes, int]]]:
    blocks: List[Tuple[bytes, int]] = []
    found = False
    for opcode, _length, payload, hdr in iter_biff_records(wb):
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

        # Workbook "절대 오프셋" 기준, 실제 문자열 바이트 각각의 위치 리스트
        self.byte_positions: List[int] = []


class SSTParser:
    def __init__(self, blocks: List[Tuple[bytes, int]]):
        self.blocks = blocks
        self.idx = 0      # 현재 어느 페이로드 블록인지
        self.pos = 0      # 해당 블록 내 현재 오프셋
        self.cur_abs = blocks[0][1]  # Workbook 절대 오프셋 기준 현재 오프셋
        self.reading_text = False    # 문자열 읽는 중인지 여부

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

        if self.reading_text and len(payload) > 0:
            self.pos = 1
            self.cur_abs += 1

    def read_n(self, n: int) -> bytes:
        out = bytearray()
        remain = n

        while remain > 0:
            payload, _abs_off = self.cur_block()
            avail = len(payload) - self.pos

            if avail <= 0:
                self.next_block()
                continue

            take = min(avail, remain)
            chunk = payload[self.pos : self.pos + take]
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
            payload, _abs_off = self.cur_block()
            avail = len(payload) - self.pos

            if avail <= 0:
                self.next_block()
                continue

            remain = total - len(out)
            take = min(remain, avail)

            start_abs = self.cur_abs
            chunk = payload[self.pos : self.pos + take]
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
        self.read_n(8)  # SST 헤더 스킵 (cstTotal, cstUnique)
        out: List[XLUCSString] = []
        while True:
            try:
                out.append(self.parse_exlucs())
            except EOFError:
                break
        return out


# 문자열 추출
def extract_sst(wb: bytes, strings: List[str]) -> List[str]:
    texts: List[str] = []
    for opcode, _length, payload, _hdr in iter_biff_records(wb):
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
        raw = payload[rgb_off : rgb_off + rgb_len]
        text = raw.decode("utf-16le", errors="ignore")
    else:
        rgb_len = cch
        raw = payload[rgb_off : rgb_off + rgb_len]
        text = raw.decode("latin1", errors="ignore")

    next_off = rgb_off + rgb_len
    raw_len = next_off - start

    return text, cch, fHigh, next_off, raw_len


def extract_headerfooter(payload: bytes, count=6):
    items: List[Dict[str, Any]] = []

    off = 0
    off += 28  # frtHeader, guidSView

    # flags
    flags = le16(payload, off)
    off += 2
    fDiffOddEven = flags & 0x0001
    fDiffFirst = (flags >> 1) & 0x0001
    print(f"[DEBUG] fDiffOddEven={fDiffOddEven}, fDiffFirst={fDiffFirst}")

    # cchHeaderEven / FooterEven / HeaderFirst / FooterFirst
    _cchHeaderEven = le16(payload, off); off += 2
    _cchFooterEven = le16(payload, off); off += 2
    _cchHeaderFirst = le16(payload, off); off += 2
    _cchFooterFirst = le16(payload, off); off += 2

    for _ in range(count):
        if off >= len(payload):
            break

        text, cch, fHigh, next_off, raw_len = parse_xlucs(payload, off)

        items.append(
            {
                "text": text,
                "cch": cch,
                "fHigh": fHigh,
                "off": off,
                "raw_len": raw_len,
            }
        )
        off = next_off

    return items


# MSODRAWING 레코드와 그 뒤의 CONTINUE 레코드를 묶어 OfficeArt 바이트 스트림으로 수집
def collect_msodrawing(wb: bytes) -> List[Dict[str, Any]]:
    recs = list(iter_biff_records(wb))
    out: List[Dict[str, Any]] = []

    i = 0
    while i < len(recs):
        op, _, payload, _ = recs[i]
        if op != MSODRAWING:
            i += 1
            continue

        start_idx = i
        chunks = [payload]

        j = i + 1
        while j < len(recs) and recs[j][0] == CONTINUE:
            chunks.append(recs[j][2])
            j += 1

        out.append({
            "start_idx": start_idx,
            "end_idx": j - 1,
            "officeart_bytes": b"".join(chunks),
        })
        i = j

    return out


# OfficeArt 스트림의 마지막 레코드가 ClientTextbox(F00D, 길이 0)인지 판별
def last_record_is_clienttextbox(officeart: bytes) -> bool:
    cur = 0
    n = len(officeart)
    last_type = None
    last_len = None

    while cur + 8 <= n:
        rv, ri, rt, rl = parse_officeArtRecordHdr(officeart, cur)
        last_type, last_len = rt, rl
        cur += 8 + rl

    # 정확히 끝까지 파싱되었는지 체크
    if cur != n:
        return False

    return (last_type == 0xF00D and last_len == 0)


# ClientTextbox 뒤에 반드시 따라야 하는 TxO 레코드의 인덱스를 명세 기준으로 수집
def collect_textbox_txo_idx(wb: bytes) -> List[int]:
    recs = list(iter_biff_records(wb))
    streams = collect_msodrawing(wb)
    txo_indices: List[int] = []

    for s in streams:
        if not last_record_is_clienttextbox(s["officeart_bytes"]):
            continue

        next_idx = s["end_idx"] + 1
        if next_idx < len(recs) and recs[next_idx][0] == TXO:
            txo_indices.append(next_idx)

    return txo_indices


# TxO의 cchText / cbRuns 값이 명세 조건을 만족하는지 검사
def txo_spec_satisfy(cchText: int, cbRuns: int) -> bool:
    if cchText == 0:
        return cbRuns == 0
    # cchText > 0 이면 cbRuns는 16 이상 + 8의 배수
    if cbRuns < 16 or (cbRuns % 8) != 0:
        return False
    return True


# CONTINUE 레코드 집합에서 XLUnicodeStringNoCch 텍스트를 실제로 소비
def consume_text(records, start_idx: int, cchText: int):
    remain = cchText
    idx = start_idx
    text_bytes = bytearray()
    positions: List[int] = []
    last_fHigh = 0

    while idx < len(records) and remain > 0:
        cop, clen, cpayload, chdr = records[idx]
        if cop != CONTINUE or clen <= 0:
            break

        # 첫 바이트는 flags, 이후가 문자열 데이터
        flags = cpayload[0]
        fHigh = flags & 0x01
        last_fHigh = fHigh
        char_size = 2 if fHigh else 1

        data = cpayload[1:]
        abs_start = chdr + 4 + 1  # BIFF 헤더 + flags

        can_take = min(remain, len(data) // char_size)
        take_bytes = can_take * char_size

        if take_bytes:
            text_bytes.extend(data[:take_bytes])
            positions.extend(range(abs_start, abs_start + take_bytes))
            remain -= can_take

        idx += 1

    return cchText - remain, text_bytes, positions, last_fHigh, idx


# CONTINUE 레코드들의 payload 길이를 합산하여 TxORuns 공간 계산
def sum_continue_payload(records, start_idx: int) -> int:
    total = 0
    idx = start_idx
    while idx < len(records):
        cop, clen, _, _ = records[idx]
        if cop != CONTINUE or clen <= 0:
            break
        total += clen
        idx += 1
    return total


# TxO payload 내부에서 cchText / cbRuns 위치를 명세 + CONTINUE 검증으로 결정
def parse_txo_header_by_spec(records, txo_idx: int):
    _, ln, payload, _ = records[txo_idx]

    if ln < 10:
        return 4, 0, 0, 0, txo_idx + 1

    best = None # 여러 TxO 헤더 후보 중 명세와 실제 CONTINUE 구조에 가장 잘 맞는 결과를 저장

    for off in range(4, min(ln - 6, 64)):
        cchText = le16(payload, off)
        cbRuns  = le16(payload, off + 2)
        ifntEmpty = le16(payload, off + 4)

        if not txo_spec_satisfy(cchText, cbRuns):
            continue

        consumed, _, _, _, next_idx = consume_text(
            records, txo_idx + 1, cchText
        )
        if consumed != cchText:
            continue

        remain_runs = sum_continue_payload(records, next_idx)
        if cbRuns > 0 and remain_runs < cbRuns:
            continue

        score = (1000 if remain_runs == cbRuns else 0) + (100 if cchText > 0 else 0) - off
        if best is None or score > best[0]:
            best = (score, off, cchText, cbRuns, ifntEmpty, next_idx)

    if best:
        _, off, cchText, cbRuns, ifntEmpty, next_idx = best
        return off, cchText, cbRuns, ifntEmpty, next_idx

    return 4, 0, 0, 0, txo_idx + 1


# TxO 레코드에 연결된 텍스트와 해당 바이트의 절대 오프셋 목록을 추출
def read_txo_text_positions(records, txo_idx: int) -> Tuple[str, int, List[int]]:
    _, cchText, _, _, _ = parse_txo_header_by_spec(records, txo_idx)

    if cchText == 0:
        return "", 0, []

    consumed, text_bytes, positions, fHigh, _ = consume_text(
        records, txo_idx + 1, cchText
    )
    if consumed != cchText or not positions:
        return "", 0, []

    text = (
        text_bytes.decode("utf-16le", errors="ignore")
        if fHigh else
        text_bytes.decode("latin1", errors="ignore")
    )
    return text, fHigh, positions


def extract_textbox(wb: bytes) -> List[str]:
    records = list(iter_biff_records(wb))
    texts: List[str] = []

    # ClientTextbox → TxO 위치 수집
    txo_indices = collect_textbox_txo_idx(wb)

    for txo_idx in txo_indices:
        text, _fHigh, _positions = read_txo_text_positions(records, txo_idx)
        if text:
            texts.append(text)

    return texts


# msoDrawingGroup payload 모으기
def get_msoDrawingGroup(wb: bytes) -> List[Tuple[bytes, int]]:
    blocks = []
    started = False

    for opcode, length, payload, hdr in iter_biff_records(wb):
        if opcode == MSODRAWINGGROUP:
            blocks.append((payload, hdr + 4))
            started = True
        elif started and opcode == CONTINUE:
            blocks.append((payload, hdr + 4))
        elif started:
            break

    return blocks


# 각 바이트가 원본 wb의 어느 절대 오프셋에 대응되는지 positions로 기록
def concat_block_pos(blocks: List[Tuple[bytes, int]]) -> Tuple[bytes, List[int]]:
    out = bytearray()
    pos_list : List[int] = []

    for payload, abs_off, in blocks:
        out.extend(payload)
        pos_list.extend(list(range(abs_off, abs_off + len(payload))))
    return bytes(out), pos_list


# OfficeArtRecordHeader 파싱
def parse_officeArtRecordHdr(data: bytes, off: int) -> Tuple[int, int, int, int]:
    if off + 8 > len(data):
        raise EOFError("OfficeArtRecordHeader가 범위를 벗어났습니다.")
    
    ver_inst = le16(data, off)
    recVer = ver_inst & 0x000F
    recInstance = (ver_inst & 0xFFF0) >> 4
    recType = le16(data, off + 2)
    recLen = le32(data, off + 4)
    return recVer, recInstance, recType, recLen


# OfficeArt 컨테이너 내부 child record들을 순회
def iter_officeart_container_children(data: bytes, container_off: int):
    _, _, _, recLen = parse_officeArtRecordHdr(data, container_off)
    container_end = container_off + 8 + recLen
    cur = container_off + 8

    while cur + 8 <= container_end:
        rv, ri, rt, rl = parse_officeArtRecordHdr(data, cur)
        yield cur, rv, ri, rt, rl
        cur += 8 + rl

    if cur != container_end:
        raise ValueError("[ERROR] OfficeArt 컨테이너 경계 불일치")


# OfficeArtBlip의 rh 기준으로 BLIPFileData가 시작되는 오프셋을 계산
def blip_filedata_offset(recType, recInstance):
    if recType == 0xF01D:  # JPEG
        return 8 + 16 + (16 if recInstance in (0x46B, 0x6E3) else 0) + 1
    
    if recType == 0xF01E:  # PNG
        return 8 + 16 + (16 if recInstance == 0x6E1 else 0) + 1
    
    if recType == 0xF01F:  # DIB
        return 8 + 16 + (16 if recInstance == 0x7A9 else 0) + 1
    
    if recType == 0xF029:  # TIFF
        return 8 + 16 + (16 if recInstance == 0x6E5 else 0) + 1
    
    if recType in (0xF01A, 0xF01B, 0xF01C):  # EMF/WMF/PICT
        return 8 + 16 + (16 if recInstance in (0x3D5, 0x217, 0x543) else 0) + 34
    
    return None


# 이미지 치환
def patch_positions(wb: bytearray, positions: List[int], start: int, new_bytes: bytes) -> None:
    for i, b in enumerate(new_bytes):
        wb[positions[start + i]] = b

def replace_fn(img_bytes, meta):
    print("[DBG] 이미지 길이:", len(img_bytes))
    print("[DBG]] BLIP 타입:", hex(meta["blipType"]))
    return img_bytes


# MSODRAWINGGROUP(0x00EB) 안의 BStore에서 BLIPFileData를 추출
def parse_images(wb: bytearray, replace_fn=None) -> Dict[str, Any]:
    blocks = get_msoDrawingGroup(bytes(wb))
    if not blocks:
        return {"found": False, "images": 0, "patched": 0}

    # BIFF CONTINUE 연결 → OfficeArt 스트림
    data, pos = concat_block_pos(blocks)

    # OfficeArtDggContainer (0xF000)
    dgg_off = 0
    rv, ri, rt, rl = parse_officeArtRecordHdr(data, dgg_off)
    if rt != 0xF000:
        raise ValueError(
            f"[ERROR] OfficeArtDggContainer(0xF000)을 기대했으나 {hex(rt)} 레코드 발견"
        )

    # OfficeArtBStoreContainer (0xF001)
    bstore_off = None
    for off, cv, ci, ct, cl in iter_officeart_container_children(data, dgg_off):
        if ct == 0xF001:
            bstore_off = off
            break

    if bstore_off is None:
        return {
            "found": True,
            "dgg": True,
            "bstore": False,
            "images": 0,
            "patched": 0,
        }

    images = 0
    patched = 0

    # BStore child 순회
    for rec_off, rv, ri, rt, rl in iter_officeart_container_children(data, bstore_off):
        rec_start = rec_off
        rec_end = rec_off + 8 + rl

        # FBSE (0xF007)
        if rt == 0xF007:
            # FBSE 고정 영역 최소 36바이트
            if rl < 36:
                continue

            fbse_fixed = rec_start + 8
            if fbse_fixed + 36 > len(data):
                continue

            btWin32 = data[fbse_fixed + 0]
            btMacOS = data[fbse_fixed + 1]
            rgbUid  = data[fbse_fixed + 2 : fbse_fixed + 18]
            tag     = le16(data, fbse_fixed + 18)
            size    = le32(data, fbse_fixed + 20)
            cRef    = le32(data, fbse_fixed + 24)
            foDelay = le32(data, fbse_fixed + 28)
            cbName  = data[fbse_fixed + 33]

            # 빈 슬롯은 스킵
            if cRef == 0:
                continue

            # nameData 뒤
            emb_off = fbse_fixed + 36 + cbName

            # embeddedBlip 존재 여부
            if emb_off + 8 > rec_end:
                continue

            try:
                brv, bri, brt, brl = parse_officeArtRecordHdr(data, emb_off)
            except Exception:
                continue

            blip_end = emb_off + 8 + brl
            if blip_end > rec_end:
                continue

            fd_off = blip_filedata_offset(brt, bri)
            if fd_off is None:
                continue

            filedata_start = emb_off + fd_off
            filedata_end   = blip_end
            if filedata_end > len(data):
                continue

            blip_bytes = data[filedata_start:filedata_end]
            images += 1

            if replace_fn is not None:
                new_bytes = replace_fn(
                    blip_bytes,
                    {
                        "blipType": brt,
                        "btWin32": btWin32,
                        "btMacOS": btMacOS,
                        "rgbUid": rgbUid,
                        "tag": tag,
                        "size": size,
                        "cRef": cRef,
                        "foDelay": foDelay,
                    },
                )

                # 길이 보존
                if len(new_bytes) < len(blip_bytes):
                    new_bytes += b"\x00" * (len(blip_bytes) - len(new_bytes))
                elif len(new_bytes) > len(blip_bytes):
                    new_bytes = blip_bytes

                patch_positions(wb, pos, filedata_start, new_bytes)
                patched += 1

        # 단독 OfficeArtBlip
        elif rt in (
            0xF01A,  # EMF
            0xF01B,  # WMF
            0xF01C,  # PICT
            0xF01D,  # JPEG
            0xF01E,  # PNG
            0xF01F,  # DIB
            0xF029,  # TIFF
            0xF02A,
        ):
            fd_off = blip_filedata_offset(rt, ri)
            if fd_off is None:
                continue

            filedata_start = rec_start + fd_off
            filedata_end   = rec_end
            if filedata_end > len(data):
                continue

            blip_bytes = data[filedata_start:filedata_end]
            images += 1

            if replace_fn is not None:
                new_bytes = replace_fn(blip_bytes, {"blipType": rt})

                if len(new_bytes) < len(blip_bytes):
                    new_bytes += b"\x00" * (len(blip_bytes) - len(new_bytes))
                elif len(new_bytes) > len(blip_bytes):
                    new_bytes = blip_bytes

                patch_positions(wb, pos, filedata_start, new_bytes)
                patched += 1

            print("[DBG] BLIP 헤더:", blip_bytes[:8].hex())
            with open(f"debug_img_{images}.bin", "wb") as f:
                f.write(blip_bytes)

    return {
        "found": True,
        "dgg": True,
        "bstore": True,
        "images": images,
        "patched": patched,
    }


def redact_xlucs(text: str, extra_literals: Optional[List[str]] = None) -> str:
    if not text:
        return text

    norm_text, index_map = normalization_index(text)

    spans = find_sensitive_spans(norm_text)
    spans = spans or []

    # NER/스팬 기반 리터럴도 동일 길이로 추가 마스킹
    lits = [str(x).strip() for x in (extra_literals or []) if str(x).strip()]
    lits = sorted(set([x for x in lits if len(x) >= 2]), key=lambda x: (-len(x), x))

    chars = list(text)
    spans = sorted(spans, key=lambda x: x[0], reverse=True)

    # 0) 리터럴 우선(부분 문자열 충돌 방지)
    if lits:
        for lit in lits:
            masked = mask_except_hypen_at(lit)
            if not lit or lit not in text:
                continue
            # 뒤에서부터 치환(인덱스 안정)
            start = 0
            while True:
                pos = text.find(lit, start)
                if pos == -1:
                    break
                start = pos + 1
                # 기록
                s = pos
                e = pos + len(lit)
                for i, ch in enumerate(masked):
                    chars[s + i] = ch

    for s_norm, e_norm, _value, _rule in spans:
        s = index_map.get(s_norm)
        e = index_map.get(e_norm - 1)
        if s is None or e is None:
            continue
        e = e + 1

        original_seg = text[s:e]
        masked_seg = mask_except_hypen_at(original_seg)

        if len(masked_seg) != len(original_seg):
            raise ValueError("마스킹 후 길이 불일치")

        for i, ch in enumerate(masked_seg):
            chars[s + i] = ch

    return "".join(chars)


def redact_hdr_fdr(wb: bytearray, extra_literals: Optional[List[str]] = None) -> None:
    for opcode, length, payload, hdr in iter_biff_records(wb):
        if opcode in (HEADER, FOOTER):
            text, _cch, fHigh, _next_off, _raw_len = parse_xlucs(payload, 0)
            if not text:
                continue

            new_text = redact_xlucs(text, extra_literals=extra_literals)
            if len(new_text) != len(text):
                raise ValueError("Header/Footer 레닥션 길이 불일치")

            raw = encode_masked_text(new_text, fHigh)

            # record header 4B + XLUCS header 3B
            rgb_start = hdr + 4 + 3
            wb[rgb_start : rgb_start + len(raw)] = raw

        elif opcode == HEADERFOOTER:
            items = extract_headerfooter(payload)
            base = hdr + 4  # payload 시작

            for item in items:
                text = item["text"]
                off = item["off"]
                fHigh = item["fHigh"]

                if not text:
                    continue

                new_text = redact_xlucs(text, extra_literals=extra_literals)
                if len(new_text) != len(text):
                    raise ValueError("HEADERFOOTER 레닥션 길이 불일치")

                raw = encode_masked_text(new_text, fHigh)

                # cch(2) + flags(1) 뒤가 텍스트 바이트 시작
                text_start = base + off + 3
                text_end = text_start + len(raw)
                wb[text_start:text_end] = raw


def redact_textbox(wb: bytearray, extra_literals: Optional[List[str]] = None) -> None:
    records = list(iter_biff_records(wb))
    txo_indices = collect_textbox_txo_idx(bytes(wb))

    for txo_idx in txo_indices:
        text, fHigh, positions = read_txo_text_positions(records, txo_idx)
        if not text:
            continue

        red = redact_xlucs(text, extra_literals=extra_literals) # NER / literal 기반 레닥션 (추후 필요하면 처리)
        red = mask_except_hypen_at(red)

        raw = encode_masked_text(red, fHigh)

        for i, p in enumerate(positions):
            wb[p] = raw[i]



def extract_text(file_bytes: bytes):
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("Workbook"):
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            wb = ole.openstream("Workbook").read()

        blocks = get_sst_blocks(wb)
        if blocks:
            xlucs_list = SSTParser(blocks).parse()
            strings = [x.text for x in xlucs_list]
        else:
            strings = []
        
        # 본문 텍스트
        body = extract_sst(wb, strings)

        header_texts: List[str] = []
        for opcode, _length, payload, _hdr in iter_biff_records(wb):
            if opcode in (HEADER, FOOTER):
                text, _cch, _fHigh, _next_off, _raw_len = parse_xlucs(payload, 0)
                if text:
                    header_texts.append(text)
            elif opcode == HEADERFOOTER:
                items = extract_headerfooter(payload)
                for item in items:
                    if item["text"]:
                        header_texts.append(item["text"])
        
        # 텍스트박스 텍스트
        textbox_texts = extract_textbox(wb)

        # 전체 합치기
        combined_texts = body + header_texts + textbox_texts
        full_text = "\n".join(combined_texts)

        md = extract_markdown_tables_from_xls(file_bytes)

        return {
            "body": body,
            "header_footer": header_texts,
            "textbox": textbox_texts,

            "full_text": full_text,
            "markdown": md if isinstance(md, str) and md.strip() else full_text,
            "pages": [{"page": 1, "text": full_text}],
        }

    except Exception as e:
        print("[ERROR extract]:", e)
        return {"full_text": "", "pages": [{"page": 1, "text": ""}]}


# -과 @를 제외한 민감 문자열을 *로 마스킹
def mask_except_hypen_at(orig_segment: str) -> str:
    return "".join(ch if ch in "-@" else "*" for ch in orig_segment)


#OLE 파일 교체
def overlay_workbook_stream(file_bytes: bytes, orig_wb: bytes, new_wb: bytes) -> bytes:
    full = bytearray(file_bytes)

    pos = full.find(orig_wb)
    if pos == -1:
        print("[WARN] OLE 파일에서 Workbook 스트림 위치를 찾지 못함")
        return file_bytes

    if len(orig_wb) != len(new_wb):
        raise ValueError(
            "[ERROR ! !] 동일길이 치환 실패"
            f" original={len(orig_wb)}, new={len(new_wb)}"
        )

    full[pos : pos + len(orig_wb)] = new_wb
    return bytes(full)


def redact(file_bytes: bytes, spans: Optional[List[Dict[str, Any]]] = None) -> bytes:
    print("[INFO] XLS Redaction 시작")

    extra_literals: List[str] = []
    if spans and isinstance(spans, list):
        for sp in spans:
            if not isinstance(sp, dict):
                continue
            t = sp.get("text")
            if t is None:
                continue
            v = str(t).strip()
            if len(v) >= 2:
                extra_literals.append(v)
    extra_literals = sorted(set(extra_literals), key=lambda x: (-len(x), x))

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("Workbook"):
            print("[ERROR] Workbook 없음")
            return file_bytes
        orig_wb = ole.openstream("Workbook").read()

    wb = bytearray(orig_wb)

    blocks = get_sst_blocks(wb)
    if not blocks:
        return file_bytes

    xlucs_list = SSTParser(blocks).parse()

    for x in xlucs_list:
        red_text = redact_xlucs(x.text, extra_literals=extra_literals)

        if len(red_text) != len(x.text):
            raise ValueError("동일길이 레닥션 실패 (문자 수 불일치)")

        raw = encode_masked_text(red_text, x.fHigh)

        if len(raw) != len(x.byte_positions):
            raise ValueError("raw 길이 mismatch")

        # CONTINUE-aware 바이트 패치
        for i, pos in enumerate(x.byte_positions):
            wb[pos] = raw[i]

    print("[OK] SST 텍스트 레닥션 완료")

    redact_hdr_fdr(wb, extra_literals=extra_literals)
    print("[OK] 헤더/푸터 텍스트 레닥션 완료")

    redact_textbox(wb, extra_literals=extra_literals)
    print("[OK] 텍스트박스 레닥션 완료")

    # 이미지 처리
    img = parse_images(wb, replace_fn=replace_fn)
    print(f"[OK] 이미지 위치: {img}")

    return overlay_workbook_stream(file_bytes, orig_wb, bytes(wb))