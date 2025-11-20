from __future__ import annotations
import io
import os
import time
import shutil
import zipfile
import logging
import tempfile
import subprocess
from typing import List, Optional

import fitz
from fastapi import HTTPException

# XmlScanResponse 임포트 (core 우선, 실패 시 대안 경로)
try:
    from ..core.schemas import XmlScanResponse
except Exception:
    try:
        from ..schemas import XmlScanResponse
    except Exception:
        from server.core.schemas import XmlScanResponse

# 모듈 임포트 (상대 경로 우선)
try:
    from . import docx_module as docx
except Exception:
    from server.modules import docx_module as docx

try:
    from . import xlsx_module as xlsx
except Exception:
    from server.modules import xlsx_module as xlsx

try:
    from . import pptx_module as pptx
except Exception:
    from server.modules import pptx_module as pptx

try:
    from . import hwpx_module as hwpx
except Exception:
    from server.modules import hwpx_module as hwpx

# 규칙 컴파일러
try:
    from .common import compile_rules
except Exception:
    from server.modules.common import compile_rules

log = logging.getLogger("xml_redaction")


def detect_xml_type(filename: str) -> str:
    # 확장자로 포맷 판별
    l = (filename or "").lower()
    if l.endswith(".docx"): return "docx"
    if l.endswith(".xlsx"): return "xlsx"
    if l.endswith(".pptx"): return "pptx"
    if l.endswith(".hwpx"): return "hwpx"
    raise HTTPException(400, f"Unsupported XML type for: {filename}")


def _collect_hwpx_secrets(zin: zipfile.ZipFile) -> List[str]:
    # HWPX에서 사전 매칭으로 마스킹 키워드 수집
    text = hwpx.hwpx_text(zin)
    comp = compile_rules()
    secrets: List[str] = []
    seen = set()
    for _rule, rx, _need_valid, _prio in comp:
        for m in rx.finditer(text or ""):
            v = m.group(0)
            if v and v not in seen:
                seen.add(v)
                secrets.append(v)
    return secrets


# LibreOffice 실행 파일 탐색
def _find_soffice() -> Optional[str]:
    candidates = [
        shutil.which("soffice"),
        r"C:\Program Files\LibreOffice\program\soffice.exe",
        r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
        r"/usr/bin/soffice",
        r"/usr/local/bin/soffice",
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None


def _office_to_pdf_with_soffice(in_path: str, out_dir: str) -> str:
    # 문서를 PDF로 변환
    soffice = _find_soffice()
    if not soffice:
        raise RuntimeError("LibreOffice(soffice) 실행 파일을 찾지 못했습니다.")
    cmd = [
        soffice, "--headless", "--nologo", "--nofirststartwizard",
        "--convert-to", "pdf", "--outdir", out_dir, in_path,
    ]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    dt = (time.perf_counter() - t0) * 1000
    log.info("HWPX preview regen: soffice convert done (%.1fms)", dt)
    if proc.returncode != 0:
        raise RuntimeError(f"soffice 변환 실패: {proc.stderr or proc.stdout}")

    base = os.path.splitext(os.path.basename(in_path))[0]
    pdf_name = base + ".pdf"
    pdf_path = os.path.join(out_dir, pdf_name)
    if not os.path.exists(pdf_path):
        cands = [os.path.join(out_dir, f) for f in os.listdir(out_dir) if f.lower().endswith(".pdf")]
        if not cands:
            raise RuntimeError("PDF 결과를 찾지 못했습니다.")
        pdf_path = cands[0]
    return pdf_path


def _render_pdf_to_png_bytes(pdf_path: str, dpi: int = 144) -> List[bytes]:
    # PDF → PNG 바이트 목록
    images: List[bytes] = []
    doc = fitz.open(pdf_path)
    try:
        for i in range(doc.page_count):
            page = doc.load_page(i)
            mat = fitz.Matrix(dpi / 72.0, dpi / 72.0)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            images.append(pix.tobytes("png"))
    finally:
        doc.close()
    log.info("HWPX preview regen: rendered %d page(s) at %ddpi", len(images), dpi)
    return images


def _list_preview_names(zipf: zipfile.ZipFile) -> List[str]:
    # ZIP 내 프리뷰 이미지 경로 수집
    names = []
    for n in zipf.namelist():
        nl = n.lower()
        if nl.startswith("preview/") and nl.endswith((".png", ".jpg", ".jpeg")):
            names.append(n)
    names.sort()
    return names


def _rewrite_zip_replacing_previews(
    redacted_tmp_hwpx: str,
    dst_path: str,
    new_images: List[bytes],
    original_preview_names: List[str],
) -> None:
    # 프리뷰 이미지만 새 이미지로 교체
    with zipfile.ZipFile(redacted_tmp_hwpx, "r") as zin, \
         zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED) as zout:

        if "mimetype" in zin.namelist():
            zi = zipfile.ZipInfo("mimetype")
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, zin.read("mimetype"))

        preview_names = _list_preview_names(zin)
        if not preview_names:
            if original_preview_names:
                preview_names = original_preview_names[:]
            else:
                preview_names = [f"Preview/page_{i+1:03d}.png" for i in range(len(new_images))]

        replace_map = {preview_names[i]: new_images[i] for i in range(min(len(preview_names), len(new_images)))}

        used = set()
        for item in zin.infolist():
            name = item.filename
            low = name.lower()
            if name == "mimetype":
                continue
            if low.startswith("preview/") and low.endswith((".png", ".jpg", ".jpeg")) and name in replace_map:
                zout.writestr(name, replace_map[name]); used.add(name)
            else:
                zout.writestr(item, zin.read(name))

        for n in preview_names:
            if n not in used and n in replace_map:
                zout.writestr(n, replace_map[n])

    log.info(
        "HWPX preview regen: wrote %d preview image(s) into %s",
        min(len(preview_names), len(new_images)),
        os.path.basename(dst_path),
    )


def xml_redact_to_file(src_path: str, dst_path: str, filename: str) -> None:
    # XML 포맷 레닥션 → 파일 저장
    comp = compile_rules()
    kind = detect_xml_type(filename)
    log.info("XML redact: file=%s kind=%s", filename, kind)

    original_preview_names: List[str] = []
    if kind == "hwpx":
        with zipfile.ZipFile(src_path, "r") as zin:
            try:
                secrets = _collect_hwpx_secrets(zin)
            except Exception:
                secrets = []
            original_preview_names = _list_preview_names(zin)
        hwpx.set_hwpx_secrets(secrets)
        log.info("HWPX secrets collected: %d", len(secrets))

    with tempfile.TemporaryDirectory() as td:
        tmp_redacted = os.path.join(td, os.path.splitext(os.path.basename(dst_path))[0] + ".tmp.hwpx")

        # ZIP 항목 순회하며 파트별 레닥션
        with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(tmp_redacted, "w", zipfile.ZIP_DEFLATED) as zout:
            if kind == "hwpx" and "mimetype" in zin.namelist():
                zi = zipfile.ZipInfo("mimetype")
                zi.compress_type = zipfile.ZIP_STORED
                zout.writestr(zi, zin.read("mimetype"))

            kept = dropped = modified = 0

            def _write(item, red: Optional[bytes], data: bytes):
                nonlocal kept, dropped, modified
                if red is None:
                    zout.writestr(item, data); kept += 1
                elif isinstance(red, (bytes, bytearray)) and len(red) == 0:
                    dropped += 1
                else:
                    zout.writestr(item, red); modified += 1

            for item in zin.infolist():
                name = item.filename
                data = zin.read(name)

                if kind == "docx":
                    _write(item, docx.redact_item(name, data, comp), data)
                elif kind == "xlsx":
                    _write(item, xlsx.redact_item(name, data, comp), data)
                elif kind == "pptx":
                    _write(item, pptx.redact_item(name, data, comp), data)
                elif kind == "hwpx":
                    _write(item, hwpx.redact_item(name, data, comp), data)
                else:
                    zout.writestr(item, data); kept += 1

            log.info("%s ZIP result: kept=%d modified=%d dropped=%d", kind.upper(), kept, modified, dropped)

        # 프리뷰 재생성 옵션
        regen = (os.getenv("HWPX_REGEN_PREVIEW", "0") in ("1", "true", "TRUE"))
        if kind == "hwpx" and regen:
            log.info("HWPX preview regen: start (env HWPX_REGEN_PREVIEW=1)")
            try:
                pdf_path = _office_to_pdf_with_soffice(tmp_redacted, td)
                dpi = int(os.getenv("HWPX_PREVIEW_DPI", "144") or "144")
                images = _render_pdf_to_png_bytes(pdf_path, dpi=dpi)
                if not images:
                    log.warning("HWPX preview regen: 렌더 결과 없음 → 원본 프리뷰 유지")
                    shutil.copyfile(tmp_redacted, dst_path)
                else:
                    _rewrite_zip_replacing_previews(
                        redacted_tmp_hwpx=tmp_redacted,
                        dst_path=dst_path,
                        new_images=images,
                        original_preview_names=original_preview_names,
                    )
            except Exception as e:
                log.warning("HWPX preview regen 실패 → 원본 프리뷰 유지 (%s)", e)
                shutil.copyfile(tmp_redacted, dst_path)
        else:
            shutil.copyfile(tmp_redacted, dst_path)

    if kind == "hwpx":
        hwpx.set_hwpx_secrets([])
    log.info("HWPX redact done" if kind == "hwpx" else "XML redact done")