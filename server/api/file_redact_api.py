from fastapi import APIRouter, UploadFile, File, Response, HTTPException, Form
from pathlib import Path
from server.modules import doc_module, hwp_module, ppt_module, xls_module, pdf_module
import json

router = APIRouter(prefix="/redact", tags=["redact"])

@router.post("/file", response_class=Response)
async def redact_file(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()
    out, mime, fname = None, "application/octet-stream", f"redacted{ext}"

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
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )

@router.post("/replace_doc", response_class=Response)
async def replace_text_in_doc(
    file: UploadFile = File(...),
    targets: str = Form(..., description="치환할 문자열 목록 (JSON 배열 형태)"),
    replacement_char: str = Form(default="*", description="치환 문자"),
    preserve_dashes: bool = Form(default=True, description="하이픈(-) 보존 여부")
):
    """
    DOC 파일에서 특정 문자열을 동일 길이로 치환
    """
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()
    
    if ext != ".doc":
        raise HTTPException(400, f"현재 DOC 파일만 지원됩니다. 받은 확장자: {ext}")
    
    try:
        # JSON 파싱
        targets_list = json.loads(targets)
        if not isinstance(targets_list, list):
            raise ValueError("targets는 문자열 배열이어야 합니다")
        
        # DOC 치환 실행
        out = doc_module.replace_text(file_bytes, targets_list, replacement_char)
        
        if not out:
            raise HTTPException(500, "DOC 치환 실패: 출력 없음")
        
        # 치환 횟수 계산
        replacements_count = 0
        for target in targets_list:
            replacements_count += file_bytes.count(target.encode('utf-8'))
        
        return Response(
            content=out,
            media_type="application/msword",
            headers={
                "Content-Disposition": f'attachment; filename="replaced_{file.filename}"',
                "X-Replacements-Count": str(replacements_count)
            }
        )
        
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"targets JSON 파싱 오류: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"DOC 치환 중 오류: {e}")
