from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import devices, configs, terminal, schedules, auth
from app.core.config import settings
from app.core.database import engine
from app.models import base


@asynccontextmanager
async def lifespan(app: FastAPI):
    # DB テーブル作成
    async with engine.begin() as conn:
        await conn.run_sync(base.Base.metadata.create_all)
    yield


app = FastAPI(
    title="NetConfig Manager API",
    description="ネットワーク機器のコンフィグ収集・世代管理システム",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
app.include_router(configs.router, prefix="/api/configs", tags=["configs"])
app.include_router(terminal.router, prefix="/api/terminal", tags=["terminal"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
