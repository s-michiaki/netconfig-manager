"""API の一覧（Swagger UI の代わり。外部のスクリプトを使わない）

- FastAPI 既定の /docs（Swagger UI）・/redoc は CDN（cdn.jsdelivr.net）のスクリプトを、版の固定も改ざんの検出もなしで、
  アプリと同じオリジンに読み込む。CDN が改ざんされると、開いた人の localStorage のトークンを読まれるおそれがあるため使わない
- 一覧は OpenAPI のスキーマ（app.openapi()）から作る。HTML はスクリプトを含まない表だけ（画面と同じ厳しい CSP でも表示できる）
- DOCS_ENABLED=true のときだけ /docs と /openapi.json を出す（開発用。本番の nginx は中継しない）。
  本番では backend のコンテナで `python -m app.tools.api_list` を実行して見る（ログインなしで見られる場所を作らない）
"""
from html import escape

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.token_policy import TOKEN_ALLOWED

METHODS = ("get", "post", "put", "patch", "delete")


def api_rows(app: FastAPI) -> list[dict]:
    """API の一覧（パス順）: [{"method", "path", "summary", "tags", "token"}]。token は API トークンで呼べるか"""
    rows = []
    for path, ops in sorted(app.openapi().get("paths", {}).items()):
        for m in METHODS:
            op = ops.get(m)
            if not op:
                continue
            key = f"{m.upper()} {path}"
            rows.append({"method": m.upper(), "path": path, "summary": op.get("summary") or "",
                         "tags": ", ".join(op.get("tags") or []), "token": key in TOKEN_ALLOWED})
    return rows


def render_html(app: FastAPI) -> str:
    """一覧の HTML（スクリプト・外部の読み込みなし。値はすべて逃がす）"""
    body = "\n".join(
        f"<tr><td>{escape(r['method'])}</td><td><code>{escape(r['path'])}</code></td><td>{escape(r['summary'])}</td>"
        f"<td>{escape(r['tags'])}</td><td>{'可' if r['token'] else '-'}</td></tr>"
        for r in api_rows(app)
    )
    title = escape(f"{app.title} {app.version}")
    return (
        "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">"
        f"<title>{title}</title>"
        "<style>body{font-family:sans-serif;margin:1.5em}table{border-collapse:collapse}"
        "td,th{border:1px solid #ccc;padding:.25em .5em;text-align:left;vertical-align:top}</style>"
        "</head><body>"
        f"<h1>{title}</h1>"
        "<p>OpenAPI のスキーマ（全項目）: <a href=\"/openapi.json\">/openapi.json</a>。"
        "「トークン」が「可」の API は、API トークン（Authorization: Bearer ncm_…）で呼べます。</p>"
        "<table><thead><tr><th>メソッド</th><th>パス</th><th>概要</th><th>分類</th><th>トークン</th></tr></thead>"
        f"<tbody>\n{body}\n</tbody></table></body></html>"
    )


def install_api_docs(app: FastAPI) -> None:
    """/docs（一覧の HTML）と /openapi.json を足す（DOCS_ENABLED のときだけ呼ぶ）"""

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_json():
        return JSONResponse(app.openapi())

    @app.get("/docs", include_in_schema=False, response_class=HTMLResponse)
    async def api_docs():
        return HTMLResponse(render_html(app))
