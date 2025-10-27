from fastapi import APIRouter, UploadFile, File, Response, HTTPException, Form
from pathlib import Path
from server.modules import doc_module, hwp_module, ppt_module, xls_module, pdf_module

router = APIRouter(prefix="/redact", tags=["redact"])

@router.post("/file", response_class=Response)
async def redact_file(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()
    out, mime, fname = None, "application/octet-stream", file.filename  # 원본 파일명 유지
    encoded_fileName = file.filename.encode("utf-8", "ignore").decode("latin-1", "ignore") #한국어 인코딩처리

    try:
        if ext == ".doc":
            out = doc_module.redact(file_bytes)
            mime = "application/msword"
        elif ext == ".hwp":
            out = hwp_module.redact(file_bytes)
            mime = "application/x-hwp"
        elif ext == ".ppt":
            out = ppt_module.redact(file_bytes)
            mime = "application/vnd.ms-powerpoint"
        elif ext == ".xls":
            out = xls_module.redact(file_bytes)
            mime = "application/vnd.ms-excel"
        elif ext == ".pdf":
            out = pdf_module.apply_text_redaction(file_bytes)
            mime = "application/pdf"
        else:
            raise HTTPException(400, f"지원하지 않는 포맷: {ext}")
    except Exception as e:
        raise HTTPException(500, f"{ext} 처리 중 오류: {e}")

    if not out:
        raise HTTPException(500, f"{ext} 레닥션 실패: 출력 없음")

    return Response(
        content=out,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{encoded_fileName}"'}
    )

