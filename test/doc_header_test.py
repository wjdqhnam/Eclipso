import struct, olefile

def le16(b, off): 
    return struct.unpack_from("<H", b, off)[0]

def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]


with olefile.OleFileIO("test.doc") as ole:
    word_data = ole.openstream("WordDocument").read()

    # fWhichTblStm 플래그 확인
    fib_base_flags = struct.unpack_from("<H", word_data, 0x000A)[0]
    fWhichTblStm = (fib_base_flags & 0x0200) != 0
    tbl_stream = "1Table" if fWhichTblStm else "0Table"

    #fComplex확인
    fComplex = (fib_base_flags & 0x0004) != 0

    # Table 스트림 읽기
    table_data = ole.openstream(tbl_stream).read()

base_len = 32
csw = le16(word_data, 32)
fibRgW_len = csw * 2
cslw = le16(word_data, 32 + 2 + fibRgW_len) # fibRgW 길이 + csw길이까지 포함
fibRgLw_off = 32 + 2 + fibRgW_len + 2
fibRgLw_len = cslw * 4

#ccpHdd 읽기
ccpHdd = le32(word_data, fibRgLw_off + 0x0C)

cbRgFcLcb_off = fibRgLw_off + fibRgLw_len
cbRgFcLcb = le16(word_data, cbRgFcLcb_off)
fibRgFcLcbBlob_off = cbRgFcLcb_off + 2
fibRgFcLcbBlob_len = cbRgFcLcb * 8

#fcPlcHdd, lcbPlcHdd 읽기
index = 11
off = fibRgFcLcbBlob_off + index * 8
fcPlcHdd = le32(word_data, off)
lcbPlcHdd = le32(word_data, off + 4)

#PlcfHdd 읽기
plcfhdd = table_data[fcPlcHdd : fcPlcHdd + lcbPlcHdd]
count = len(plcfhdd) // 4
aCP = struct.unpack_from(f"<{count}I", plcfhdd)

story = []
for i in range(len(aCP) - 2):
    start_cp, end_cp = aCP[i], aCP[i + 1]
    if start_cp == end_cp:
        continue
    story.append((start_cp, end_cp))



#출력
fib = {
    "tbl_stream" : tbl_stream,
    "fComplex" : fComplex,
    "base_len": base_len,
    "csw": csw,
    "fibRgW_len": fibRgW_len,
    "cslw": cslw,
    "fibRgLw_off": fibRgLw_off,
    "fibRgLw_len": fibRgLw_len,
    "ccpHdd": ccpHdd,
    "cbRgFcLcb_off": cbRgFcLcb_off,
    "cbRgFcLcb": cbRgFcLcb,
    "fibRgFcLcbBlob_off": fibRgFcLcbBlob_off,
    "fibRgFcLcbBlob_len": fibRgFcLcbBlob_len,
}

for name, value in fib.items():
    print(f"{name} = {value}")

print(f"fcPlcHdd = {fcPlcHdd} (0x{fcPlcHdd:08X})") #16진수 8자리 포맷 출력
print(f"lcbPlcHdd = {lcbPlcHdd} (0x{lcbPlcHdd:08X})")
print(f"aCP count = {len(aCP)}")

for i, (start, end) in enumerate(story): #인덱스와 값 동시에 꺼내기
    print(f"Story {i}: CP {start} ~ {end - 1}")
