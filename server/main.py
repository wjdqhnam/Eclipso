from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from server.api import text_api, redaction_api, file_redact_api

app = FastAPI(title="Eclipso Redaction Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(text_api.router)
app.include_router(redaction_api.router)
app.include_router(file_redact_api.router)

@app.get("/health")
async def health():
    return {"status": "ok"}
