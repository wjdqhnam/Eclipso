from fastapi import APIRouter, UploadFile, HTTPException
from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text

router = APIRouter(prefix="/text", tags=["text"])

@router.post("/extract")
async def extract_text(file: UploadFile):
    try:
        return await extract_from_file(file)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(500, detail=f"서버 내부 오류: {e}")

@router.get("/rules")
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]

@router.post("/match")
async def match(req: dict):
    text = req.get("text", "")
    return match_text(text)
