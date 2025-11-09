from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter

NER_API_URL = os.getenv(
    "NER_API_URL",
    "https://tjwls100-eclipso-ner-api.hf.space/predict",
)
NER_TIMEOUT_MS = int(os.getenv("NER_TIMEOUT_MS", "3000"))
NER_MAX_RETRY = int(os.getenv("NER_MAX_RETRY", "1"))

class NerAPIError(Exception):
    pass

router = APIRouter(prefix="/ner", tags=["ner"])

@router.get(
    "/health",
    summary="NER 연동 상태 확인",
    description=(
        "상태 확인. URL 노출. 타임아웃(ms) 노출. "
        "외부 NER 엔드포인트 접근 전 기본 점검 용도."
    ),
)
async def health() -> Dict[str, Any]:
    return {"ok": True, "url": NER_API_URL, "timeout_ms": NER_TIMEOUT_MS}

@router.post(
    "/predict",
    summary="NER 호출 프록시",
    description="""본문 NER 예측. 입력: text, labels(옵션).
외부 NER API로 위임.
응답: ok, latency_ms, raw(원본 응답).

테스트 예시:
{ "text": "홍길동의 이메일은 test@example.com 입니다.", "labels": ["PS","email","LC"] }""",
)
async def predict_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = (payload or {}).get("text", "") or ""
    labels = (payload or {}).get("labels", None)
    res = await ner_predict_async(text=text, labels=labels)
    return res

async def ner_predict_async(text: str, labels: Optional[List[str]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"text": text}
    if labels:
        payload["labels"] = labels

    timeout = httpx.Timeout(NER_TIMEOUT_MS / 1000.0)
    last_exc: Optional[Exception] = None
    for _ in range(max(1, NER_MAX_RETRY + 1)):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                t0 = time.time()
                resp = await client.post(NER_API_URL, json=payload)
                latency_ms = int((time.time() - t0) * 1000)
                resp.raise_for_status()
                data = resp.json()
                return {"ok": True, "latency_ms": latency_ms, "raw": data}
        except Exception as e:
            last_exc = e
    raise NerAPIError(str(last_exc))

def ner_predict_blocking(text: str, labels: Optional[List[str]] = None) -> Dict[str, Any]:
    import requests
    payload: Dict[str, Any] = {"text": text}
    if labels:
        payload["labels"] = labels
    t0 = time.time()
    try:
        r = requests.post(NER_API_URL, json=payload, timeout=NER_TIMEOUT_MS / 1000.0)
        r.raise_for_status()
        data = r.json()
        latency_ms = int((time.time() - t0) * 1000)
        return {"ok": True, "latency_ms": latency_ms, "raw": data}
    except Exception as ex:
        return {"ok": False, "latency_ms": int((time.time() - t0) * 1000), "raw": {"error": str(ex)}}
