from fastapi import UploadFile, HTTPException
from server.modules import doc_module, ppt_module, xls_module, hwp_module, pdf_module

MODULE_MAP = {
    ".doc": doc_module,
    ".ppt": ppt_module,
    ".xls": xls_module,
    ".hwp": hwp_module,
    ".pdf": pdf_module,
}

async def extract_from_file(file: UploadFile):
    filename = (file.filename or "").lower()
    ext = "." + filename.split(".")[-1]
    mod = MODULE_MAP.get(ext)
    if not mod:
        raise HTTPException(415, f"지원하지 않는 확장자: {ext}")
    file_bytes = await file.read()
    return mod.extract_text(file_bytes)
