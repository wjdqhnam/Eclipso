import io, struct, olefile
from server.core.redaction_rules import apply_redaction_rules

SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD
LABEL = 0x0204
LABEL_R1C1 = 0x0203

def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        off += 4
        payload = data[off:off + length]
        off += length
        yield opcode, payload

def collect_sst_chunks(wb: bytes):
    chunks = []
    collecting = False
    for opcode, payload in iter_biff_records(wb):
        if opcode == SST:
            collecting = True
            chunks.append(payload)
        elif collecting and opcode == CONTINUE:
            chunks.append(payload)
        elif collecting:
            break
    return chunks

class ChunkReader:
    """CONTINUE-aware reader"""
    def __init__(self, chunks):
        self.chunks = chunks
        self.i = 0
        self.pos = 0

    def _bytes_left(self):
        return len(self.chunks[self.i]) - self.pos if self.i < len(self.chunks) else 0

    def _next_chunk(self):
        self.i += 1
        self.pos = 0

    def read(self, n: int) -> bytes:
        out = b""
        while n > 0 and self.i < len(self.chunks):
            left = self._bytes_left()
            if left == 0:
                self._next_chunk()
                continue
            take = min(left, n)
            out += self.chunks[self.i][self.pos:self.pos + take]
            self.pos += take
            n -= take
        return out

def extract_text_from_xls(file_bytes: bytes):
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("Workbook"):
                print("Workbook 스트림 없음")
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}
            wb = ole.openstream("Workbook").read()

        chunks = collect_sst_chunks(wb)
        reader = ChunkReader(chunks)
        if not chunks:
            print("SST 없음")
            return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

        num_total, num_unique = struct.unpack_from("<II", reader.read(8))
        strings = []
        for _ in range(num_unique):
            if reader.i >= len(reader.chunks):
                break
            try:
                cch = struct.unpack("<H", reader.read(2))[0]
                flags = struct.unpack("B", reader.read(1))[0]
                is_unicode = flags & 0x01
                txt_bytes = reader.read(cch * (2 if is_unicode else 1))
                txt = txt_bytes.decode("utf-16le" if is_unicode else "latin1", errors="ignore").strip()
                strings.append(txt)
            except Exception:
                continue

        texts = []
        for opcode, payload in iter_biff_records(wb):
            if opcode == LABELSST and len(payload) >= 10:
                idx = struct.unpack_from("<I", payload, 6)[0]
                if 0 <= idx < len(strings):
                    texts.append(strings[idx])
            elif opcode == LABEL and len(payload) > 8:
                try:
                    txt = payload[8:].decode("cp949", errors="ignore").strip()
                    if txt:
                        texts.append(txt)
                except Exception:
                    continue

        full_text = "\n".join(t for t in texts if t)
        print(f"XLS 텍스트 추출 완료: {len(texts)} 셀 수집됨")
        return {"full_text": full_text, "pages": [{"page": 1, "text": full_text}]}

    except Exception as e:
        print("XLS 추출 중 예외:", e)
        return {"full_text": "", "pages": [{"page": 1, "text": ""}]}


def redact(file_bytes: bytes) -> bytes:
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("Workbook"):
            return file_bytes
        wb = bytearray(ole.openstream("Workbook").read())

    off = 0
    while off + 4 < len(wb):
        opcode, length = struct.unpack_from("<HH", wb, off)
        off += 4
        payload_off = off
        payload_end = off + length

        if opcode in (0x00FC, 0x00FD, 0x0204):  # SST, LABELSST, LABEL
            chunk = wb[payload_off:payload_end]
            try:
                text = chunk.decode("utf-16le", errors="ignore") or chunk.decode("cp949", errors="ignore")
                red = apply_redaction_rules(text)
                enc = red.encode("utf-16le")
                wb[payload_off:payload_end] = enc[:length].ljust(length, b"\x00")
            except Exception:
                pass

        off = payload_end

    return bytes(wb)

def extract_text(file_bytes: bytes) -> dict:
    return extract_text_from_xls(file_bytes)
