import io
import os
import sys
import zlib
import olefile

CFB = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
GZ  = b"\x1F\x8B"

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)
    print(f"[OK] wrote: {path}")

def try_deflate(raw: bytes):
    """
    deflate/zlib만 시도
    """
    for wbits in (-15, +15):
        try:
            dec = zlib.decompress(raw, wbits)
            print(f"[OK] decompress success wbits={wbits} in={len(raw)} out={len(dec)}")
            return dec, wbits
        except Exception:
            pass
    print("[FAIL] not deflate/zlib")
    return None, None

def magic_hits(raw: bytes):
    hits = []
    if raw.startswith(CFB):
        hits.append(("ole", 0))
    for sig, name in [(CFB, "ole"), (GZ, "gzip")]:
        off = raw.find(sig, 1)
        if off != -1:
            hits.append((name, off))
    return hits

def main():
    if len(sys.argv) < 2:
        print("usage: python hwp_deflate_dump.py <file.hwp>")
        return

    hwp_path = sys.argv[1]
    out_dir = "out"
    ensure_dir(out_dir)

    with olefile.OleFileIO(hwp_path) as ole:
        streams = ole.listdir(streams=True, storages=False)

        for path in streams:
            if not (len(path) == 2 and path[0] == "BinData" and path[1].endswith(".OLE")):
                continue

            name = path[1]
            raw = ole.openstream(path).read()

            print(f"\n=== {name} ===")
            print(f"[OK] extracted raw size={len(raw)}")

            raw_path = os.path.join(out_dir, f"{name}.raw")
            write_file(raw_path, raw)

            dec, wbits = try_deflate(raw)
            if not dec:
                continue

            dec_path = os.path.join(out_dir, f"{name}.dec")
            write_file(dec_path, dec)

            mags = magic_hits(dec)
            print(f"[INFO] magic_hits={mags}")

            # OLE가 안에 있으면 그대로 잘라서 떨굼
            for kind, off in mags:
                if kind == "ole":
                    inner = dec[off:]
                    inner_path = os.path.join(out_dir, f"{name}.inner.ole")
                    write_file(inner_path, inner)

if __name__ == "__main__":
    main()