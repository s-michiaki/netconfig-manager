"""#39: API の一覧（/docs・/openapi.json）の公開範囲と、CDN のスクリプトを使わない一覧（app/core/api_docs.py）のテスト

- 既定（DOCS_ENABLED=false）では /docs・/redoc・/openapi.json のルートが無い（ログインなしで見られる場所を作らない）
- DOCS_ENABLED のときの /docs は、スクリプト・外部の読み込みを含まない HTML（値は逃がす）
- 本番で一覧を見るための python -m app.tools.api_list
"""
import json
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient

from app.core import api_docs
from app.core.config import settings
from app.main import app

BACKEND = Path(__file__).resolve().parents[1]


def test_docs_are_disabled_by_default():
    assert settings.DOCS_ENABLED is False
    paths = {rc.path for rc in iter_route_contexts(app.routes)}
    for p in ("/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"):
        assert p not in paths, p
    assert app.docs_url is None and app.redoc_url is None and app.openapi_url is None
    c = TestClient(app)  # 起動処理（DB）は不要（with を使わない）
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(p).status_code == 404, p


def _sample_app():
    a = FastAPI(title="T", version="9", docs_url=None, redoc_url=None, openapi_url=None)

    @a.get("/api/devices/", summary='<script>alert("x")</script> 一覧', tags=["devices"])
    async def devices():
        return []

    @a.post("/api/x/{x_id}", summary="作る")
    async def make(x_id: int):
        return {}

    api_docs.install_api_docs(a)
    return a


def test_enabled_docs_page_has_no_scripts_or_external_resources():
    a = _sample_app()
    c = TestClient(a)
    r = c.get("/docs")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    html = r.text
    assert "<script" not in html.lower()  # 概要の <script> も逃がしてある
    assert "&lt;script&gt;" in html
    assert "http://" not in html and "https://" not in html and "cdn" not in html.lower()
    assert "/api/devices/" in html and "/api/x/{x_id}" in html
    # GET /api/devices/ は API トークンで呼べる（token_policy.TOKEN_ALLOWED）。サンプルの POST は呼べない
    rows = {(r["method"], r["path"]): r for r in api_docs.api_rows(a)}
    assert rows[("GET", "/api/devices/")]["token"] is True and rows[("POST", "/api/x/{x_id}")]["token"] is False
    spec = c.get("/openapi.json").json()
    assert "/api/devices/" in spec["paths"] and "/docs" not in spec["paths"]


def test_api_list_tool_prints_routes_without_db():
    """本番で一覧を見る手段（ホストから backend のコンテナで実行する）。DB・Redis に接続せずに出せる"""
    r = subprocess.run([sys.executable, "-m", "app.tools.api_list"], cwd=BACKEND, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert any(line.startswith("GET    /api/devices/") and " token " in line for line in lines), r.stdout[:500]
    assert any(line.startswith("POST   /api/auth/tokens") and " - " in line for line in lines)
    r = subprocess.run([sys.executable, "-m", "app.tools.api_list", "--json"], cwd=BACKEND, capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    assert "/api/health" in json.loads(r.stdout)["paths"]
