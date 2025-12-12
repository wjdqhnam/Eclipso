from __future__ import annotations
import io
import os
import sys
import zlib
import olefile

# =========================
# util
# =========================

def write_file(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"[OK] wrote: {path}")

def safe_filename(name: str) -> str:
    """
    Windows 파일명에서 사용할 수 없는 문자 / 제어문자 제거
    """
    out = []
    for ch in name:
        o = ord(ch)
        if o < 0x20 or ch in '<>:"/\\|?*':
            out.append("_")
        else:
            out.append(ch)
    return "".join(out).strip("_")

# =========================
# magic / compression
# =========================

CFB = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
PNG = b"\x89PNG\r\n\x1a\n"
GZ  = b"\x1F\x8B"

def magic_hits(raw: bytes):
    hits = []
    if raw.startswith(CFB):
        hits.append(("ole", 0))
    if raw.startswith(PNG):
        hits.append(("png", 0))
    if raw.startswith(GZ):
        hits.append(("gzip", 0))

    for sig, name in [(CFB, "ole"), (PNG, "png"), (GZ, "gzip")]:
        off = raw.find(sig, 1)
        if off != -1:
            hits.append((name, off))
    return hits

def try_decompress(raw: bytes):
    for w in (-15, +15):
        try:
            dec = zlib.decompress(raw, w)
            print(f"[OK] decompress success wbits={w} in={len(raw)} out={len(dec)}")
            return dec, w
        except Exception:
            pass
    return None, None

# =========================
# extract BINxxxx.OLE
# =========================

def extract_bindata_ole(hwp_path: str, out_dir: str):
    with olefile.OleFileIO(hwp_path) as ole:
        for path in ole.listdir(streams=True, storages=False):
            if len(path) == 2 and path[0] == "BinData" and path[1].endswith(".OLE"):
                raw = ole.openstream(path).read()
                name = path[1]
                out_path = os.path.join(out_dir, f"{name}.raw")
                write_file(out_path, raw)
                return raw, name
    return None, None

# =========================
# inner OLE dump
# =========================

def dump_inner_ole_streams(inner_ole_path: str, out_dir: str):
    ole = olefile.OleFileIO(inner_ole_path)

    print("\n=== INNER OLE STORAGES ===")
    for s in ole.listdir(streams=False, storages=True):
        print("/", "/".join(s))

    print("\n=== INNER OLE STREAMS ===")
    for s in ole.listdir(streams=True, storages=False):
        raw_name = "/".join(s)
        safe = safe_filename(raw_name)

        print("/", raw_name)

        try:
            data = ole.openstream(s).read()
        except Exception as e:
            print(f"[WARN] cannot read stream {raw_name}: {e}")
            continue

        out_path = os.path.join(out_dir, safe + ".bin")
        write_file(out_path, data)

    ole.close()

# =========================
# main
# =========================

def main():
    if len(sys.argv) != 2:
        print("usage: python hwp_inner.py <file.hwp>")
        sys.exit(1)

    hwp_path = sys.argv[1]
    out_root = "out"
    os.makedirs(out_root, exist_ok=True)

    # 1. BINxxxx.OLE 추출
    raw, name = extract_bindata_ole(hwp_path, out_root)
    if not raw:
        print("[FAIL] BinData/*.OLE not found")
        return

    print(f"[OK] extracted {name} raw size={len(raw)}")

    # 2. deflate 해제 시도
    dec, wbits = try_decompress(raw)
    if not dec:
        print("[FAIL] cannot decompress BinData")
        return

    dec_path = os.path.join(out_root, f"{name}.dec")
    write_file(dec_path, dec)

    # 3. magic 검사
    hits = magic_hits(dec)
    print(f"[INFO] magic_hits={hits}")

    ole_off = None
    png_off = None
    for k, o in hits:
        if k == "ole" and ole_off is None:
            ole_off = o
        if k == "png" and png_off is None:
            png_off = o

    print(f"[INFO] ole_offset={ole_off} png_offset={png_off}")

    if ole_off is None:
        print("[FAIL] inner OLE not found")
        return

    # 4. inner OLE / chart image 분리
    inner_ole = dec[ole_off:png_off] if png_off else dec[ole_off:]
    inner_ole_path = os.path.join(out_root, "inner.ole")
    write_file(inner_ole_path, inner_ole)

    if png_off:
        png = dec[png_off:]
        write_file(os.path.join(out_root, "chart.png"), png)

    # 5. inner OLE stream dump
    dump_dir = os.path.join(out_root, "streams")
    dump_inner_ole_streams(inner_ole_path, dump_dir)

if __name__ == "__main__":
    main()
