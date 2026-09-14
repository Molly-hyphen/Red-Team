import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "AegisPentest Platform"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # LLM Settings
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gemini-3.7-flash")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    LOCAL_LLM_URL: str = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./pentest.db")
    
    # Concurrency and Limits
    MAX_AGENT_CONCURRENCY: int = int(os.getenv("MAX_AGENT_CONCURRENCY", "5"))
    MAX_CHILD_AGENTS_PER_PARENT: int = 4
    MAX_ITERATIONS_PER_AGENT: int = 15
    MAX_SCAN_DURATION_SECONDS: int = 1800
    MAX_TOKENS_PER_SCAN: int = 150000
    TOOL_TIMEOUT_SECONDS: int = 30
    
    # Sandbox
    SANDBOX_MODE: str = os.getenv("SANDBOX_MODE", "docker")
    SANDBOX_IMAGE: str = os.getenv("SANDBOX_IMAGE", "aegis-sandbox:latest")
    
    # Security
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = ["*"]
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
