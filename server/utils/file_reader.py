from fastapi import UploadFile, HTTPException
from server.modules import doc_module, docx_module, ppt_module, pptx_module, xls_module, xlsx_module, hwp_module, hwpx_module, pdf_module

MODULE_MAP = {
    ".doc": doc_module,
    ".docx": docx_module,  # 추가
    ".ppt": ppt_module,
    ".pptx": pptx_module,  # 추가
    ".xls": xls_module,
    ".xlsx": xlsx_module,  # 추가
    ".hwp": hwp_module,
    ".hwpx": hwpx_module,  # 추가
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
