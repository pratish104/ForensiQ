from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    # Database and Redis
    database_url: str = "postgresql+psycopg://postgres:password@localhost:5432/forensiq"
    redis_url: str = "redis://localhost:6379"
    
    # Security
    secret_key: str = "change-this-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    
    # File handling
    upload_dir: str = "./uploads"
    max_file_size_mb: int = 50

    # New Pydantic V2 way to handle .env files
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()

# Create a global instance for easy access
settings = get_settings()