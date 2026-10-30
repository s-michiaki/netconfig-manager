from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_SECRETS = {"change-me-in-production", "changeme", "secret", "your_jwt_secret_key_here"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+asyncpg://netconfig:changeme@localhost:5432/netconfig"
    REDIS_URL: str = "redis://localhost:6379/0"
    GIT_REPO_PATH: str = "/app/configs"
    TIMEZONE: str = "Asia/Tokyo"

    # --- 認証 ---
    # 必須。デフォルト値は持たせない（未設定・弱い値なら起動時にエラー）
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    # ユーザーが1人もいないときに作成する初期管理者
    ADMIN_USERNAME: str = "admin"
    # 未設定の場合はランダムなパスワードを生成し、起動ログに一度だけ出力する
    ADMIN_PASSWORD: str | None = None

    # --- 機器パスワードの暗号化（Fernetキー）---
    DEVICE_ENCRYPTION_KEY: str

    # カンマ区切り。フロントを同一オリジン（Viteプロキシ / nginx）で配信する場合は空でよい
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    # --- SSH ---
    SSH_TIMEOUT: int = 30
    SSH_AUTH_TIMEOUT: int = 20
    # 機器の応答待ち時間（秒）の既定値。ログイン後のプロンプト待ち・コマンド実行の待ちに使う。
    # 機器ごとに上書き可能（デバイス設定の「応答待ち時間」）
    SSH_READ_TIMEOUT: int = Field(default=120, ge=10, le=600)
    SSH_KNOWN_HOSTS: str = "/data/ssh/known_hosts"
    # tofu  : 初回接続時にホスト鍵を記録し、以後は一致を検証（鍵が変わったら接続拒否）
    # strict: known_hosts に無いホストへの接続を拒否
    SSH_HOST_KEY_POLICY: Literal["tofu", "strict"] = "tofu"

    @field_validator("ADMIN_PASSWORD", mode="before")
    @classmethod
    def _empty_to_none(cls, v):
        # docker-compose で ${ADMIN_PASSWORD:-} のように空文字が渡された場合は未設定扱い
        return v or None

    @field_validator("SECRET_KEY")
    @classmethod
    def _check_secret_key(cls, v: str) -> str:
        if v in _WEAK_SECRETS or len(v) < 32:
            raise ValueError(
                "SECRET_KEY は32文字以上のランダムな値を設定してください "
                "(例: python -c \"import secrets; print(secrets.token_urlsafe(48))\")"
            )
        return v

    @field_validator("DEVICE_ENCRYPTION_KEY")
    @classmethod
    def _check_fernet_key(cls, v: str) -> str:
        from cryptography.fernet import Fernet

        try:
            Fernet(v.encode())
        except Exception as e:  # noqa: BLE001
            raise ValueError(
                "DEVICE_ENCRYPTION_KEY が不正です "
                "(例: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")"
            ) from e
        return v

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]


settings = Settings()
