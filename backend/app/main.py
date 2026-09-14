from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.scans import router as scans_router
from app.api.general import router as general_router
from app.tools import tool_registry

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous AI penetration testing platform with multi-agent orchestration, scope enforcement, and verified findings."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router, prefix=settings.API_PREFIX)
app.include_router(general_router, prefix=settings.API_PREFIX)

@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "version": settings.VERSION,
        "llm_provider": settings.LLM_PROVIDER,
        "tools_registered": len(tool_registry.list_tools())
    }

@app.get("/api/tools")
async def list_tools():
    return tool_registry.list_tools()
