import io, os, struct, tempfile, olefile
from typing import List, Dict, Any, Tuple, Optional, Set

from server.core.normalize import normalization_index
from server.core.matching import find_sensitive_spans


SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD
LABEL = 0x0204
NUMBER = 0x0203
RK = 0x027E
BOUNDSHEET = 0x0085
EOF = 0x000A
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
    """
    Workbook 글로벌 스트림에서 BOUNDSHEET들을 읽어 (시트명, 시트BOF오프셋) 리스트 반환.
    """
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
    """
    시트 서브스트림에서 LABELSST/NUMBER/LABEL을 기반으로 간단한 셀 그리드를 복원.
    """
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
                if r + 1 > max_rows or c + 1 > max_cols:
                    continue
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
    """
    XLS(OLE/BIFF)에서 시트별 표 형태를 최대한 복원하여 markdown(HTML table 포함)을 생성.
    """
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



def extract_text_from_xls(file_bytes: bytes) -> dict:
    """레거시 XLS(OLE/BIFF)에서 텍스트를 추출한다."""
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
        md = extract_markdown_tables_from_xls(file_bytes)

        return {
            "body": body,
            "header_footer": header_texts,
            "full_text": full_text,
            "markdown": md if isinstance(md, str) and md.strip() else full_text,
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


def redact(file_bytes: bytes, spans: Optional[List[Dict[str, Any]]] = None) -> bytes:
    """
    XLS(레거시 OLE/BIFF) 레닥션.
    - 규칙/정규식 기반으로 탐지된 텍스트 + NER spans에서 추출한 텍스트를 'secrets'로 모아
      OLE 스트림 전반에 대해 동일 길이 마스킹을 적용한다(파일 크기 보존).
    """
    try:
        from .ole_redactor import redact_ole_bin_preserve_size
    except Exception:
        try:
            from ole_redactor import redact_ole_bin_preserve_size
        except Exception:
            redact_ole_bin_preserve_size = None

    if redact_ole_bin_preserve_size is None:
        return file_bytes

    try:
        text = (extract_text(file_bytes) or {}).get("full_text", "") or ""
    except Exception:
        text = ""

    secrets: List[str] = []

    # 1) 기존 룰(정규식) 기반 추출(텍스트에서 value만)
    try:
        from server.core.normalize import normalization_text
        norm = normalization_text(text)
        for _s, _e, val, _meta in find_sensitive_spans(norm):
            v = str(val or "").strip()
            if len(v) >= 2:
                secrets.append(v)
    except Exception:
        pass

    # 2) NER spans에서 텍스트 추출
    if spans and isinstance(text, str) and text:
        n = len(text)
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
            seg = text[s:e].strip()
            if len(seg) >= 2:
                secrets.append(seg)

    # 3) 정리
    if not secrets:
        return file_bytes
    uniq: List[str] = []
    seen: Set[str] = set()
    for s in sorted(secrets, key=lambda x: (-len(x), x)):
        if s not in seen:
            seen.add(s)
            uniq.append(s)

    try:
        return redact_ole_bin_preserve_size(file_bytes, uniq, mask_preview=False)
    except Exception:
        return file_bytes

def extract_text(file_bytes: bytes) -> dict:
    """text_api.py 에서 호출되는 공통 인터페이스"""
    return extract_text_from_xls(file_bytes)
