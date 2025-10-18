import io, olefile

with open("test.doc", "rb") as f:
    raw = f.read()

print("len(raw) =", len(raw))
print("Header =", raw[:8].hex())

# 정상
olefile.OleFileIO(io.BytesIO(raw))

# 비정상 (고의로 seek을 안 함)
buf = io.BytesIO(raw)
buf.read()  # EOF로 이동
try:
    olefile.OleFileIO(buf)
except Exception as e:
    print("에러 발생:", e)
