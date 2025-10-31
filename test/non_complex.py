import olefile
import struct

def le16(b, off): 
    return struct.unpack_from("<H", b, off)[0]

def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]

with olefile.OleFileIO("test.doc") as ole:
    word_data = ole.openstream("WordDocument").read()

    # fWhichTblStm 플래그 확인
    fib_base_flags = le16(word_data, 0x000A)
    fWhichTblStm = (fib_base_flags & 0x0200) != 0
    tbl_stream = "1Table" if fWhichTblStm else "0Table"

        # Table 스트림 읽기
    table_data = ole.openstream(tbl_stream).read()

#fComplex확인
fComplex = (fib_base_flags & 0x0004) != 0


fcMin = le32(word_data, 0x0018)
fcMac = le32(word_data, 0x001C)
ccpText = le32(word_data, 0x004C)    # main document text length
ccpFtn  = le32(word_data, 0x0050)    # footnote length
ccpHdr  = le32(word_data, 0x0054)    # header/footer length

#계산
doc_start = fcMin
doc_end = fcMin + ccpText

ftn_start = doc_end
ftn_end = ftn_start + ccpFtn

hdr_start = ftn_end
hdr_end = hdr_start + ccpHdr


# 출력
print(f"fComplex: {fComplex}")
print(f"fcMin: 0x{fcMin:08X} ({fcMin})")
print(f"fcMac: 0x{fcMac:08X} ({fcMac})")

print(f"doc_area (ccpText): 0x{doc_start:08X} ~ 0x{doc_end - 1:08X} ({ccpText})")
print(f"footnote_area (ccpFtn): 0x{ftn_start:08X} ~ 0x{ftn_end - 1:08X} ({ccpFtn})")
print(f"header_area (ccpHdr): 0x{hdr_start:08X} ~ 0x{hdr_end - 1:08X} ({ccpHdr})")

# ------ 압축여부 확인 ------
# FIB에서 fcClx, lcbClx 읽기
fcClx = le32(word_data, 0x01A2)
lcbClx = le32(word_data, 0x01A6)

print("WordDocument 스트림 크기:", len(word_data))
print(f"fcClx = {hex(fcClx)} ({fcClx})")
print(f"lcbClx = {hex(lcbClx)} ({lcbClx})")
print(f"이 문서는 {'1Table' if fWhichTblStm else '0Table'} 스트림입니다.")
print("Table 스트림 크기:", len(table_data))

#Clx 블록 추출
if lcbClx == 0:
    raise ValueError("CLX 길이가 0입니다 (텍스트 조각 정보 없음)")
if fcClx + lcbClx > len(table_data):
    raise ValueError("CLX 범위가 테이블 스트림을 벗어납니다")
clx = table_data[fcClx:fcClx + lcbClx]
print("CLx 크기:", len(clx), "bytes")
print("Clx 시작 바이트:", clx[:16])

#CLx 안에서 PlcPcd 추출
def extract_plcpcd(clx: bytes) -> bytes:
    i = 0
    while i < len(clx):
        tag = clx[i]
        i += 1
        if tag == 0x01:  # Prc
            if i + 2 > len(clx):
                raise ValueError("잘못된 Clx: Prc 헤더가 짧음")
            cb = struct.unpack_from("<H", clx, i)[0]
            i += 2 + cb

        elif tag == 0x02:  # Pcdt
            if i + 4 > len(clx):
                raise ValueError("잘못된 Clx: Pcdt 길이 누락")
            lcb = struct.unpack_from("<I", clx, i)[0]
            i += 4
            if i + lcb > len(clx):
                raise ValueError("잘못된 Clx: PlcPcd 범위 초과")
            return clx[i:i+lcb]  # 정상 반환
        
        else:
            raise ValueError(f"알 수 없는 CLX 태그: 0x{tag:02X}")

    raise ValueError("Clx 안에서 Pcdt(0x02)를 찾지 못했음")

plcpcd = extract_plcpcd(clx)
print("PlcPcd 크기: ",len(plcpcd))
print(plcpcd.hex())

def parse_plcpcd(plcpcd: bytes):
    size = len(plcpcd)
    if (size - 4) % 12 != 0:
        raise ValueError("PlcPcd 길이가 예상 형식(4*(n+1)+8*n)에 맞지 않습니다")
    n = (size - 4) // 12  # size = 4*(n+1) + 8*n (n은 조각 개수)
    
    # aCp 배열 읽기
    acp = [struct.unpack_from("<I", plcpcd, 4*i)[0] for i in range(n+1)]
    
    #PCD 배열 시작 위치
    pcd_off = 4 * (n+1)
    
    pieces = []
    for k in range(n):
        pcd_bytes = plcpcd[pcd_off + 8*k : pcd_off + 8*(k+1)] #PCD = 8byte
        flags = struct.unpack_from("<H", pcd_bytes, 0)[0] #앞 2바이트는 flag

        #이후 4바이트 = fc
        fc_raw = struct.unpack_from("<I", pcd_bytes, 2)[0]

        # fcRaw 해석
        fc = fc_raw & 0x3FFFFFFF  # 하위 30비트만
        fCompressed = (fc_raw & 0x40000000) != 0
        print(f"fc_raw=0x{fc_raw:08X}, fc={fc}, fCompressed={fCompressed}")
        
        prm    = struct.unpack_from("<H", pcd_bytes, 6)[0]

        cp_start = acp[k]
        cp_end   = acp[k+1]
        char_count = cp_end - cp_start
        byte_count = char_count if fCompressed else char_count * 2

        pieces.append({
            "piece_index": k,
            "cp_start": cp_start,
            "cp_end": cp_end,
            "char_count": char_count,
            "flags": flags,
            "fc": fc,
            "fCompressed": fCompressed,
            "byte_count": byte_count,
            "prm": prm
        })
    
    return pieces

pieces = parse_plcpcd(plcpcd)
print("조각 개수:", len(pieces))
for p in pieces[:5]:
    print(p)


def decode_piece(chunk: bytes, fCompressed: bool) -> str:
    if fCompressed:
        text = chunk.decode("cp1252", errors="replace") #1 byte
    else:
        text = chunk.decode("utf-16le", errors="replace")  #2 byte
    # Normalize newlines so CR (\r) doesn't overwrite prints in console
    # Word often uses CRLF; sometimes lone CR can appear in pieces
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text

#텍스트 추출
def extract_full_text(word_data: bytes, pieces):
    texts = []
    for i, p in enumerate(pieces):
        #WordDocument에서 해당 조각의 바이트 범위 잘라오기
        start_pos = p["fc"]
        end_pos = p["fc"] + p["byte_count"]
        
        print(f"조각 {i}: fc={p['fc']}, byte_count={p['byte_count']}, fCompressed={p['fCompressed']}")
        print(f" 범위: {start_pos} ~ {end_pos} (WordDocument 크기: {len(word_data)})")
        
        if end_pos > len(word_data):
            print(f"경고: 조각이 WordDocument 범위를 벗어남!")
            continue
            
        chunk = word_data[start_pos:end_pos]
        print(f"추출된 바이트: {len(chunk)} bytes")
        print(f"바이트 내용 (hex): {chunk[:20].hex()}...")
        
        text = decode_piece(chunk, p["fCompressed"])
        # Escape control characters for debug visibility
        debug_text = text.encode('unicode_escape').decode('ascii')
        print(f"디코딩된 텍스트: '{debug_text}'")
        print()
        
        texts.append(text)
    return "".join(texts)

full_text = extract_full_text(word_data, pieces)
# For final output, show visible newlines
visible_text = full_text
print("==== 추출된 텍스트 ====")
print(visible_text)