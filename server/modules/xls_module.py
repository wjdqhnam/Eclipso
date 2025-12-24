from __future__ import annotations

import io
import os
import struct
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.normalize import normalization_index
from server.core.matching import find_sensitive_spans


SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD
HEADER = 0x0014
FOOTER = 0x0015
HEADERFOOTER = 0x089C
BOF = 0x0809
EOF = 0x000A
BOUNDSHEET = 0x0085
CODEPAGE = 0x0042
NUMBER = 0x0203
RK = 0x027E
MULRK = 0x00BD
BOOLERR = 0x0205
FORMULA = 0x0006


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
        payload = data[off : off + length]
        off += length
        yield opcode, length, payload, header_off


def iter_biff_records_from(data: bytes, start_off: int):
    off, n = int(start_off), len(data)
    off = max(0, min(off, n))
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        header_off = off
        off += 4
        payload = data[off : off + length]
        off += length
        yield opcode, length, payload, header_off


def _codepage_to_encoding(cp: int) -> str:
    # 자주 나오는 코드페이지만 매핑, 나머지는 안전하게 latin1 fallback
    if cp == 949:
        return "cp949"
    if cp == 1252:
        return "cp1252"
    if cp == 65001:
        return "utf-8"
    return "latin1"


def _parse_codepage(wb: bytes) -> str:
    try:
        for opcode, _length, payload, _hdr in iter_biff_records(wb):
            if opcode == CODEPAGE and len(payload) >= 2:
                cp = le16(payload, 0)
                return _codepage_to_encoding(int(cp))
    except Exception:
        pass
    return "cp949"


def _decode_rk(rk: int) -> float:
    # RK value decoding (BIFF8)
    # bit0: /100, bit1: integer
    div100 = rk & 0x01
    is_int = rk & 0x02
    if is_int:
        v = rk >> 2
        # 30-bit signed
        if v & (1 << 29):
            v -= (1 << 30)
        out = float(v)
    else:
        raw64 = (rk & 0xFFFFFFFC) << 34
        out = struct.unpack("<d", struct.pack("<Q", raw64))[0]
    if div100:
        out = out / 100.0
    return out


def _fmt_num(x: float) -> str:
    try:
        if abs(x - int(x)) < 1e-9:
            return str(int(x))
    except Exception:
        pass
    # 과도한 소수 자릿수 방지
    s = f"{x:.10g}"
    return s


def _parse_boundsheets(wb: bytes, enc: str) -> List[Tuple[str, int]]:
    sheets: List[Tuple[str, int]] = []
    in_globals = False
    try:
        for opcode, _length, payload, _hdr in iter_biff_records(wb):
            if opcode == BOF and len(payload) >= 4:
                # payload: version(2) + type(2)
                sub_type = le16(payload, 2)
                in_globals = (sub_type == 0x0005)
                continue

            if in_globals and opcode == BOUNDSHEET and len(payload) >= 8:
                off = le32(payload, 0)
                name_len = payload[6]
                opt = payload[7]
                is_unicode = bool(opt & 0x01)
                name_bytes = payload[8:]
                if is_unicode:
                    raw = name_bytes[: name_len * 2]
                    name = raw.decode("utf-16le", errors="ignore")
                else:
                    raw = name_bytes[: name_len]
                    try:
                        name = raw.decode(enc, errors="ignore")
                    except Exception:
                        name = raw.decode("latin1", errors="ignore")
                name = (name or "").strip() or f"Sheet{len(sheets) + 1}"
                sheets.append((name, int(off)))
                continue

            if in_globals and opcode == EOF:
                break
    except Exception:
        return sheets

    return sheets


def _sheet_cells_to_tsv(wb: bytes, sheet_off: int, strings: List[str], *, max_rows: int = 200, max_cols: int = 60) -> str:
    cells: Dict[Tuple[int, int], str] = {}
    max_r = -1
    max_c = -1

    for opcode, _length, payload, _hdr in iter_biff_records_from(wb, sheet_off):
        if opcode == EOF:
            break

        try:
            if opcode == LABELSST and len(payload) >= 10:
                r = le16(payload, 0)
                c = le16(payload, 2)
                idx = le32(payload, 6)
                v = strings[idx] if 0 <= idx < len(strings) else ""
                v = (v or "").strip()
                if v:
                    cells[(r, c)] = v
                    max_r = max(max_r, r)
                    max_c = max(max_c, c)

            elif opcode == NUMBER and len(payload) >= 14:
                r = le16(payload, 0)
                c = le16(payload, 2)
                num = struct.unpack("<d", payload[6:14])[0]
                v = _fmt_num(float(num))
                if v:
                    cells[(r, c)] = v
                    max_r = max(max_r, r)
                    max_c = max(max_c, c)

            elif opcode == RK and len(payload) >= 10:
                r = le16(payload, 0)
                c = le16(payload, 2)
                rk = le32(payload, 6)
                v = _fmt_num(_decode_rk(int(rk)))
                if v:
                    cells[(r, c)] = v
                    max_r = max(max_r, r)
                    max_c = max(max_c, c)

            elif opcode == MULRK and len(payload) >= 6 + 2 + 2:
                r = le16(payload, 0)
                c_first = le16(payload, 2)
                last_col = le16(payload, len(payload) - 2)
                n = int(last_col) - int(c_first) + 1
                pos = 4
                for i in range(max(0, n)):
                    if pos + 6 > len(payload) - 2:
                        break
                    rk = le32(payload, pos + 2)
                    v = _fmt_num(_decode_rk(int(rk)))
                    if v:
                        c = int(c_first) + i
                        cells[(r, c)] = v
                        max_r = max(max_r, r)
                        max_c = max(max_c, c)
                    pos += 6

            elif opcode == BOOLERR and len(payload) >= 8:
                r = le16(payload, 0)
                c = le16(payload, 2)
                val = payload[6]
                is_err = payload[7]
                if is_err == 0:
                    v = "TRUE" if val else "FALSE"
                    cells[(r, c)] = v
                    max_r = max(max_r, r)
                    max_c = max(max_c, c)

            elif opcode == FORMULA and len(payload) >= 14:
                r = le16(payload, 0)
                c = le16(payload, 2)
                # 결과가 숫자일 때만 반영(문자열/에러는 뒤 STRING 레코드 필요)
                res = payload[6:14]
                if len(res) == 8 and not (res[6] == 0xFF and res[7] == 0xFF):
                    num = struct.unpack("<d", res)[0]
                    v = _fmt_num(float(num))
                    if v:
                        cells[(r, c)] = v
                        max_r = max(max_r, r)
                        max_c = max(max_c, c)
        except Exception:
            continue

    if max_r < 0 or max_c < 0:
        return ""

    max_r = min(int(max_r), max_rows - 1)
    max_c = min(int(max_c), max_cols - 1)

    lines: List[str] = []
    for r in range(max_r + 1):
        row = []
        for c in range(max_c + 1):
            v = cells.get((r, c), "")
            row.append(str(v).replace("\t", " ").strip())
        lines.append("\t".join(row).rstrip())

    return "\n".join(lines).strip()


def xls_table_text(wb: bytes, strings: List[str]) -> str:
    enc = _parse_codepage(wb)
    sheets = _parse_boundsheets(wb, enc)
    if not sheets:
        return ""

    blocks: List[str] = []
    for name, off in sheets[:3]:
        tsv = _sheet_cells_to_tsv(wb, off, strings)
        if not tsv.strip():
            continue
        blocks.append(f"[{name}]")
        blocks.append(tsv)
        blocks.append("")

    return "\n".join(blocks).strip()


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

        # 문자열이 CONTINUE로 이어질 때: 첫 1바이트는 인코딩 플래그가 끼어드는 경우가 있으므로 소비
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

            # 각 바이트의 "Workbook 절대 오프셋" 기록 (CONTINUE 대응 패치용)
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

        # 1) 표 형태 TSV(가능하면) -> UI에서 테이블로 렌더링
        table = xls_table_text(wb, strings)

        # 2) fallback 텍스트(기존 방식)
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

        # table이 있으면 "표"만 출력(중복 출력 방지)
        if table.strip():
            full_text = table.strip()
        else:
            combined_texts = body + header_texts
            full_text = "\n".join(combined_texts)

        return {
            "body": body,
            "header_footer": header_texts,
            "full_text": full_text,
            "markdown": full_text,
            "pages": [{"page": 1, "text": full_text}],
        }

    except Exception as e:
        print("[ERROR extract]:", e)
        return {"full_text": "", "pages": [{"page": 1, "text": ""}]}


def mask_except_hypen(orig_segment: str) -> str:
    out_chars: List[str] = []
    for ch in orig_segment:
        out_chars.append("-" if ch == "-" else "*")
    return "".join(out_chars)


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
            masked = mask_except_hypen(lit)
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
        masked_seg = mask_except_hypen(original_seg)

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


# OLE 파일 교체 (원본/대체 Workbook 스트림 길이 불변 전제)
def overlay_workbook_stream(file_bytes: bytes, orig_wb: bytes, new_wb: bytes) -> bytes:
    full = bytearray(file_bytes)

    pos = full.find(orig_wb)
    if pos == -1:
        print("[WARN] workbook 스트림을 전체 파일에서 찾기 실패")
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

    return overlay_workbook_stream(file_bytes, orig_wb, bytes(wb))