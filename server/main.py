from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from server.api import text_api, redaction_api, file_redact_api, ner_api

app = FastAPI(title="Eclipso Redaction Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우터 등록
app.include_router(text_api.router)
app.include_router(redaction_api.router)
app.include_router(file_redact_api.router)
app.include_router(ner_api.router)      

@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Eclipso Redaction Server is running"}

@app.get("/health", include_in_schema=False)
async def health():
    return {"ok": True}