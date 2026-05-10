from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://netconfig:changeme@localhost:5432/netconfig"
    REDIS_URL: str = "redis://localhost:6379/0"
    GIT_REPO_PATH: str = "/app/configs"
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # SSH接続デフォルト設定
    SSH_TIMEOUT: int = 30
    SSH_AUTH_TIMEOUT: int = 20

    class Config:
        env_file = ".env"


settings = Settings()
