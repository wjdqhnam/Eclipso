from __future__ import annotations

import io
import os
import time
import struct
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# --- 외부 의존성: olefile ---
try:
    import olefile
except Exception as e:
    # 서버 부팅 시 바로 원인 파악 가능하도록 명확히 알림
    raise RuntimeError(
        "olefile 패키지가 필요합니다. 가상환경에서 `pip install olefile` 수행하세요."
    ) from e

log = logging.getLogger("ole_redactor")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    log.addHandler(_h)
    log.propagate = False
log.setLevel(logging.INFO)

# --- 상수/유틸 ---
ENDOFCHAIN = 0xFFFFFFFE
MINI_CUTOFF_DEFAULT = 4096
HEAD_PREVIEW_BYTES = 96


def _hexdump(b: bytes, width: int = 16) -> str:
    return " ".join(f"{x:02X}" for x in b[:width])


def _dump_text(b: bytes, n: int) -> str:
    s = b.decode("utf-8", "ignore").replace("\r", " ").replace("\n", " ")
    return s[:n] + ("..." if len(s) > n else "")


def _prepare_dump_dir() -> Optional[Path]:
    if os.getenv("OLE_DEBUG_DUMP", "0") not in ("1", "true", "TRUE"):
        return None
    p = Path("./_ole_debug") / str(int(time.time() * 1000))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _is_cfbf(h: bytes) -> bool:
    return h.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")


# --------- 동일 길이 치환 유틸(시크릿/이메일) ---------
def utf16_same_len_replace_with_logs(data: bytes, old: str):
    old_u16 = old.encode("utf-16le")
    ba = bytearray(data)
    cnt = 0
    i = 0
    n = len(old_u16)
    if n == 0:
        return data, 0
    while True:
        j = ba.find(old_u16, i)
        if j == -1:
            break
        ba[j : j + n] = ("*" * (n // 2)).encode("utf-16le")
        cnt += 1
        i = j + n
    return bytes(ba), cnt


def visible_replace_keep_len_with_logs(data: bytes, old: str):
    changed, direct = utf16_same_len_replace_with_logs(data, old)
    if direct:
        return changed, direct
    if len(data) < 2 or (len(data) % 2):
        return data, 0
    try:
        u16 = list(struct.unpack("<" + "H" * (len(data) // 2), data))
    except struct.error:
        return data, 0
    target = list(struct.unpack("<" + "H" * len(old), old.encode("utf-16le")))
    m = len(target)
    if m == 0:
        return data, 0
    total = 0
    i = 0
    while i < len(u16):
        j = 0
        k = i
        while j < m and k < len(u16):
            if u16[k] < 0x20:
                k += 1
                continue
            if u16[k] == target[j]:
                j += 1
                k += 1
            else:
                break
        if j == m:
            p = i
            filled = 0
            while p < k and filled < m:
                if u16[p] >= 0x20:
                    u16[p] = 0x002A
                    filled += 1
                p += 1
            total += 1
            i = k
        else:
            i += 1
    return struct.pack("<" + "H" * len(u16), *u16), total


_ASCII_EMAIL_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
_ASCII_EMAIL_DOTOK = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def _mask_emails_ascii_same_len(b: bytes) -> Tuple[bytes, int]:
    ba = bytearray(b)
    hits = 0
    i = 0
    n = len(ba)
    while i < n:
        if ba[i] != 0x40:  # '@'
            i += 1
            continue
        L = i - 1
        while L >= 0 and ba[L] in _ASCII_EMAIL_CHARS:
            L -= 1
        L += 1
        R = i + 1
        had_dot = False
        while R < n and (ba[R] in _ASCII_EMAIL_DOTOK or ba[R] == 0x2E):
            if ba[R] == 0x2E:
                had_dot = True
            R += 1
        if L < i and R > i + 1 and had_dot:
            ba[L:R] = b"*" * (R - L)
            hits += 1
            i = R
        else:
            i += 1
    return bytes(ba), hits


def _mask_emails_utf16le_same_len(b: bytes) -> Tuple[bytes, int]:
    if len(b) < 4 or (len(b) % 2):
        return b, 0
    u = list(struct.unpack("<" + "H" * (len(b) // 2), b))
    hits = 0
    i = 0

    def _is_name(ch):  # name 파트 허용
        return (48 <= ch <= 57) or (65 <= ch <= 90) or (97 <= ch <= 122) or ch in (0x2E, 0x5F, 0x25, 0x2B, 0x2D)

    def _is_dom(ch):  # 도메인 파트 허용
        return (48 <= ch <= 57) or (65 <= ch <= 90) or (97 <= ch <= 122) or ch in (0x2E, 0x2D)

    while i < len(u):
        if u[i] != 0x0040:  # '@'
            i += 1
            continue
        L = i - 1
        while L >= 0 and _is_name(u[L]):
            L -= 1
        L += 1
        R = i + 1
        had_dot = False
        while R < len(u) and _is_dom(u[R]):
            if u[R] == 0x002E:
                had_dot = True
            R += 1
        if L < i and R > i + 1 and had_dot:
            for p in range(L, R):
                u[p] = 0x002A
            hits += 1
            i = R
        else:
            i += 1
    return struct.pack("<" + "H" * len(u), *u), hits


# --------- FAT/MiniFAT 쓰기 ---------
def get_root_entry(ole):
    for e in ole.direntries:
        if e and e.name == "Root Entry":
            return e
    return None


def overwrite_bigfat(ole, container: bytearray, start_sector: int, new_raw: bytes) -> int:
    s = start_sector
    pos = 0
    sec = ole.sector_size
    fat = ole.fat
    w = 0
    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        if s >= len(fat):
            break
        off = (s + 1) * sec
        chunk = new_raw[pos : pos + sec]
        container[off : off + len(chunk)] = chunk
        pos += sec
        s = fat[s]
        w += 1
    return w


def big_sector_from_minioffset(ole, root_start_sector: int, mini_offset: int) -> Tuple[Optional[int], Optional[int]]:
    sector = ole.sector_size
    block_idx = mini_offset // sector
    within = mini_offset % sector
    s = root_start_sector
    fat = ole.fat
    for _ in range(block_idx):
        if s in (-1, ENDOFCHAIN) or s >= len(fat):
            return None, None
        s = fat[s]
    return s, within


def overwrite_minifat_chain(ole, container: bytearray, mini_start: int, new_raw: bytes) -> int:
    minisize = ole.mini_sector_size
    minifat = ole.minifat
    root = get_root_entry(ole)
    if root is None:
        return 0
    root_big_start = root.isectStart
    s = mini_start
    pos = 0
    w = 0
    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        mini_off = s * minisize
        big_sector, within = big_sector_from_minioffset(ole, root_big_start, mini_off)
        if big_sector is None:
            break
        file_off = (big_sector + 1) * ole.sector_size + within
        chunk = new_raw[pos : pos + minisize]
        container[file_off : file_off + len(chunk)] = chunk
        pos += minisize
        if s >= len(minifat):
            break
        s = minifat[s]
        w += 1
    return w


def _brute_bigfat_aligned(container: bytes, sig: bytes, sector: int, max_k: int) -> Optional[int]:
    K = min(max_k, max(2, len(container) // max(1, sector)))
    for s in range(K):
        off = (s + 1) * sector
        if off + len(sig) > len(container):
            break
        if container[off : off + len(sig)] == sig:
            log.info("    · BigFAT 브루트포스(정렬) 일치: start=%d (K<=%d)", s, K)
            return s
    log.info("    · BigFAT 브루트포스(정렬) 실패: sig=%dB K=%d sector=%d", len(sig), K, sector)
    return None


def _brute_bigfat_unaligned(container: bytes, sig: bytes, sector: int, window: int = 1024 * 1024) -> Optional[int]:
    limit = min(len(container), window)
    hit = container.find(sig, sector)
    if hit == -1 or hit > limit:
        log.info("    · BigFAT 브루트포스(비정렬) 실패: first_hit=%s limit=%d", hit, limit)
        return None
    s = (hit // sector) - 1
    if s >= 0:
        log.info("    · BigFAT 브루트포스(비정렬) 근사 일치: start~=%d (file_off=%d)", s, hit)
        return s
    return None


def _brute_ministream(ole: olefile.OleFileIO, container: bytearray, stream_bytes: bytes) -> Optional[int]:
    root = get_root_entry(ole)
    if not root:
        log.info("    · MiniStream 브루트포스 실패: Root Entry 없음")
        return None
    sec_size = ole.sector_size
    fat = ole.fat
    s = root.isectStart
    mini_stream = bytearray()
    cap = 4 * 1024 * 1024
    steps = 0
    while s not in (-1, ENDOFCHAIN) and s < len(fat) and len(mini_stream) < cap:
        off = (s + 1) * sec_size
        mini_stream += container[off : off + sec_size]
        s = fat[s]
        steps += 1
        if steps > 65536:
            break
    sig = stream_bytes[: min(64, len(stream_bytes))]
    idx = mini_stream.find(sig)
    if idx == -1:
        log.info("    · MiniStream 브루트포스 실패: signature not found (sig=%dB, len=%d)", len(sig), len(mini_stream))
        return None
    mini_start = idx // ole.mini_sector_size
    log.info("    · MiniStream 브루트포스 일치: mini_start=%d (byte_off=%d)", mini_start, idx)
    return mini_start


def _probe_set(secrets: List[str]) -> Dict[str, List[bytes]]:
    return {
        "utf8": [s.encode("utf-8", "ignore") for s in (secrets or []) if s],
        "u16": [s.encode("utf-16le", "ignore") for s in (secrets or []) if s],
    }


# ------------- 메인: 프리뷰/콘텐츠 스트림 제로필 + 파이프라인 -------------
def redact_ole_bin_preserve_size(bin_bytes: bytes, secrets: List[str], *, mask_preview: bool = False) -> bytes:
    if not isinstance(bin_bytes, (bytes, bytearray, memoryview)) or len(bin_bytes) < 8:
        return bytes(bin_bytes)

    prefix_off = 0
    header = bytes(bin_bytes[:8])
    if not _is_cfbf(header):
        idx = bytes(bin_bytes).find(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
        if idx < 0:
            return bytes(bin_bytes)  # CFBF 아님
        prefix_off = idx
        log.info("BinData: CFBF 시그니처가 오프셋 %d에서 시작 (prefix=%s)", idx, _hexdump(bytes(bin_bytes)[:idx], 8))

    container = bytearray(bin_bytes)  # 수정 가능한 버퍼
    base = memoryview(container)[prefix_off:]
    dump_dir = _prepare_dump_dir()
    if dump_dir:
        (dump_dir / "ole_before.bin").write_bytes(base.tobytes())

    with olefile.OleFileIO(io.BytesIO(base.tobytes())) as ole:
        sector = ole.sector_size
        mini = ole.mini_sector_size
        cutoff = getattr(ole, "minisector_cutoff", MINI_CUTOFF_DEFAULT)
        streams = ole.listdir(streams=True, storages=False)
        log.info("OLE 열림: streams=%d, sector=%d, mini=%d, cutoff=%d", len(streams), sector, mini, cutoff)

        env_preview = os.getenv("OLE_MASK_PREVIEW", "0") in ("1", "true", "TRUE")
        force_blank_preview = mask_preview or env_preview

        probes = _probe_set(secrets)
        changed_any = False

        def _need_force_blank(name: str) -> bool:
            n = name.lower()
            if "olepres" in n:  # OlePres000 등
                return True if force_blank_preview else False
            bare = name.split("/")[-1]
            return bare in ("Contents", "OOXMLChartContents")

        for path in streams:
            sname = "/".join(path)
            try:
                raw = ole.openstream(path).read()
            except Exception as e:
                log.warning("  · %s open 실패: %s", sname, e)
                continue

            # direntry 메타
            de_start = -1
            de_size = len(raw)
            is_mini = de_size < cutoff
            try:
                de = ole._find(path)  # private
                de_start = getattr(de, "isectStart", -1)
                de_size = getattr(de, "size", de_size)
                is_mini = de_size < cutoff
                log.info("  · %s direntry: start=%d size=%d mini=%s", sname, de_start, de_size, is_mini)
            except Exception:
                log.info("  · %s direntry: <unavailable> (size=%d mini=%s)", sname, de_size, is_mini)

            orig = raw
            changed = raw
            did_force_blank = False

            # (A) 강제 제로필 대상
            if _need_force_blank(sname):
                changed = b"\x00" * len(raw)
                did_force_blank = True
            else:
                # (B) 일반 파이프라인: 시크릿/이메일 동일 길이 마스킹
                u16_hits = 0
                ascii_hits = 0
                g_ascii = 0
                g_u16 = 0
                for s in secrets or []:
                    changed, k = utf16_same_len_replace_with_logs(changed, s)
                    u16_hits += k
                for s in secrets or []:
                    changed2, k2 = visible_replace_keep_len_with_logs(changed, s)
                    if k2:
                        changed = changed2
                        ascii_hits += k2
                changed, g1 = _mask_emails_ascii_same_len(changed)
                g_ascii += g1
                changed, g2 = _mask_emails_utf16le_same_len(changed)
                g_u16 += g2
                if any((u16_hits, ascii_hits, g_ascii, g_u16)):
                    log.info(
                        "  · %s PIPELINE: u16=%d ascii=%d gen_ascii=%d gen_u16=%d",
                        sname,
                        u16_hits,
                        ascii_hits,
                        g_ascii,
                        g_u16,
                    )

            if changed == orig:
                continue

            # 길이 유지 보정
            if len(changed) < len(orig):
                changed += b"\x00" * (len(orig) - len(changed))
            elif len(changed) > len(orig):
                changed = changed[: len(orig)]

            wrote = 0
            start_used: Optional[str] = None

            # (1) direntry 기반 쓰기
            if de_start is not None and de_start >= 0:
                if is_mini:
                    wrote = overwrite_minifat_chain(ole, base.obj, de_start, changed)
                    start_used = f"MiniFAT(dir:{de_start})"
                else:
                    wrote = overwrite_bigfat(ole, base.obj, de_start, changed)
                    start_used = f"BigFAT(dir:{de_start})"

            # (2) 정렬 브루트포스
            if wrote <= 0:
                sig = orig[: min(64, len(orig))]
                bf = _brute_bigfat_aligned(base.obj, sig, sector, max_k=8192)
                if bf is not None:
                    wrote = overwrite_bigfat(ole, base.obj, bf, changed)
                    start_used = f"BigFAT(brute-aligned:{bf})"

            # (3) 비정렬 근사
            if wrote <= 0:
                sig = orig[: min(64, len(orig))]
                bf2 = _brute_bigfat_unaligned(base.obj, sig, sector, window=2 * 1024 * 1024)
                if bf2 is not None:
                    wrote = overwrite_bigfat(ole, base.obj, bf2, changed)
                    start_used = f"BigFAT(brute-unaligned:{bf2})"

            # (4) 미니스트림 브루트포스
            if wrote <= 0:
                mini_start = _brute_ministream(ole, base.obj, orig)
                if mini_start is not None:
                    wrote = overwrite_minifat_chain(ole, base.obj, mini_start, changed)
                    start_used = f"MiniFAT(brute:{mini_start})"

            if wrote <= 0:
                log.error("  · %s WRITE 스킵/실패 (start=%s)", sname, de_start)
            else:
                log.info(
                    "  · %s WRITE ok via %s (size=%d%s)",
                    sname,
                    start_used,
                    len(changed),
                    ", forced_blank" if did_force_blank else "",
                )

            # 재검증
            try:
                with olefile.OleFileIO(io.BytesIO(base.tobytes())) as ole2:
                    try:
                        rb2 = ole2.openstream(path).read()
                    except Exception:
                        rb2 = b""
                if did_force_blank:
                    ok = rb2[: min(32, len(rb2))].count(0) >= min(32, len(rb2))
                    if not ok:
                        log.error(
                            "  · %s VERIFY FAIL(프리뷰/콘텐츠 제로필 불일치) head='%s'",
                            sname,
                            _dump_text(rb2[:HEAD_PREVIEW_BYTES], HEAD_PREVIEW_BYTES),
                        )
                    else:
                        log.info("  · %s VERIFY OK (제로필)", sname)
                        changed_any = True
                else:
                    remain = 0
                    for b in probes["utf8"]:
                        if rb2.find(b) != -1:
                            remain += 1
                    for b in probes["u16"]:
                        if rb2.find(b) != -1:
                            remain += 1
                    if remain:
                        head = _dump_text(rb2[:HEAD_PREVIEW_BYTES], HEAD_PREVIEW_BYTES)
                        log.error("  · %s VERIFY FAIL (remain=%d) head='%s'", sname, remain, head)
                    else:
                        log.info("  · %s VERIFY OK", sname)
                        changed_any = True
            except Exception as e:
                log.warning("  · %s VERIFY 예외: %s", sname, e)

    if dump_dir:
        (dump_dir / "ole_after.bin").write_bytes(base.tobytes())

    if changed_any:
        log.info("OLE 처리 완료: 일부 스트림 변경됨 (prefix=%d)", prefix_off)
    else:
        log.warning("OLE 처리 완료: 변경된 스트림 없음")
    return bytes(container)


__all__ = ["redact_ole_bin_preserve_size"]