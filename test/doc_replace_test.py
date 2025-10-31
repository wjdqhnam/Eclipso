import olefile

doc_path = "./테스트.doc"
ole = olefile.OleFileIO(doc_path) #olefile을 읽기모드로 엶

print("\n1. WordDocument 스트림 읽기")
with ole.openstream("WordDocument") as stream:
	data = bytearray(stream.read())  #bytearray여야만 수정이 가능함. 그래서 그걸로 변환시킨거

print(len(data)) #WordDoument 스트림 크기를 출력함
print(data[:64]) #앞부분의 FIB를 확인 (헥사)

print("\n2. 본문 텍스트 위치 확인")
chunk = data[0x0800:0x0810]
print(chunk)
print(f"프린트된거 =>{chunk.decode('utf-16le', errors='ignore')}")

print("\n3. 텍스트 치환")
replacement = "***".encode("utf-16le")  #분석한 pcd값에서 fCompressed =0 이어서 utf-16le로 디코딩.
data[0x0800:0x0800+len(replacement)] = replacement

#개행확인을 위해 +2해서 8바이트를 읽어내림
print(f"이걸로 치환됐음 => {data[0x0800:0x0800+len(replacement)+2].decode('utf-16le', errors='ignore')}") 

print("\n4. 수정된 스트림을 다시 저장")
ole = olefile.OleFileIO(doc_path, write_mode=True)
ole.write_stream("WordDocument", bytes(data)) #olefile은 bytes타입만 허용하므로 bytearray -> bytes로 변환
ole.close()
print("종료")