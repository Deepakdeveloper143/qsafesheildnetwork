import os
from pydantic_settings import BaseSettings
from pydantic import ConfigDict

class Settings(BaseSettings):
    # App Settings
    PROJECT_NAME: str = "PromptPurify AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Database
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "http://localhost:5432")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")

    # Security
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "super-secret-key-for-dev")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15

    # Redis for Rate Limiting
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # LLM Settings
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    
    # Github Token
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

    model_config = ConfigDict(env_file=".env", case_sensitive=True, extra="allow")

    # Database usage flag
    USE_SUPABASE: bool = bool(os.getenv('SUPABASE_URL'))

settings = Settings()
