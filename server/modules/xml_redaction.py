# server/xml_redaction.py
from __future__ import annotations
import io, zipfile, time
from typing import List, Tuple
from fastapi import HTTPException
from server.core.schemas import XmlScanResponse
from server.modules.xml_redaction import docx, xlsx, pptx, hwpx
from server.modules.common import compile_rules

def detect_xml_type(filename: str) -> str:
    l = (filename or "").lower()
    if l.endswith(".docx"): return "docx"
    if l.endswith(".xlsx"): return "xlsx"
    if l.endswith(".pptx"): return "pptx"
    if l.endswith(".hwpx"): return "hwpx"
    return "docx"


def xml_scan(file_bytes: bytes, filename: str) -> XmlScanResponse:
    with io.BytesIO(file_bytes) as bio, zipfile.ZipFile(bio, "r") as zipf:
        kind = detect_xml_type(filename)
        if kind == "xlsx":
            matches, k, text = xlsx.scan(zipf)
        elif kind == "pptx":
            matches, k, text = pptx.scan(zipf)
        elif kind == "hwpx":
            matches, k, text = hwpx.scan(zipf)
        else:
            matches, k, text = docx.scan(zipf)

        if text and len(text) > 20000:
            text = text[:20000] + "\n… (truncated)"

        return XmlScanResponse(
            file_type=k,
            total_matches=len(matches),
            matches=matches,
            extracted_text=text or ""
        )


def xml_redact_to_file(src_path: str, dst_path: str, filename: str) -> None:
    comp = compile_rules()
    kind = detect_xml_type(filename)

    with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED) as zout:
        if kind == "hwpx" and "mimetype" in zin.namelist():
            zi = zipfile.ZipInfo("mimetype")
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, zin.read("mimetype"))

        for item in zin.infolist():
            name = item.filename
            data = zin.read(name)

            if kind == "docx":
                data = docx.redact_item(name, data, comp)
                zout.writestr(item, data)

            elif kind == "xlsx":
                data = xlsx.redact_item(name, data, comp)
                zout.writestr(item, data)

            elif kind == "pptx":
                data = pptx.redact_item(name, data, comp)
                zout.writestr(item, data)

            elif kind == "hwpx":
                red = hwpx.redact_item(name, data, comp)
                if red is None:
                    zout.writestr(item, data)
                elif red == b"":
                    continue
                else:
                    zout.writestr(item, red)

            else:
                zout.writestr(item, data)
