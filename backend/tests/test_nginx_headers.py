"""本番の nginx 設定（frontend/nginx/）のセキュリティヘッダーを静的に確認する

nginx を動かさずに、設定ファイルの書き方の誤り（HTTP に HSTS を付ける、location で add_header を使って
継承が切れる、CSP を緩めすぎる など）を検出する。実際のブラウザでの確認は画面テストの csp プロジェクトで行う
"""
import re
from pathlib import Path

import pytest

NGINX = Path(__file__).resolve().parents[2] / "frontend" / "nginx"

# backend だけをマウントしたコンテナで pytest を実行した場合は frontend が無いので飛ばす
pytestmark = pytest.mark.skipif(not NGINX.is_dir(), reason="frontend/nginx が見つからない")


def read(name: str) -> str:
    """設定ファイルをコメントを除いて読む"""
    text = (NGINX / name).read_text(encoding="utf-8")
    return "\n".join(line.split("#", 1)[0].rstrip() for line in text.splitlines())


def csp_values() -> dict[str, str]:
    """csp.inc の map から {キー: CSP} を取り出す"""
    return dict(re.findall(r'^\s*(\S+)\s+"([^"]+)";', read("csp.inc"), re.M))


def directives(csp: str) -> dict[str, list[str]]:
    out = {}
    for part in csp.split(";"):
        words = part.split()
        if words:
            out[words[0]] = words[1:]
    return out


def test_hsts_only_on_https():
    https = read("https.conf")
    m = re.search(r'add_header Strict-Transport-Security "([^"]+)" always;', https)
    assert m, "https.conf に HSTS が無い"
    # 自己管理の CA で運用するため短め（1 日）。サブドメインを巻き込まない・preload しない
    assert m.group(1) == "max-age=86400"
    # 443 の server にだけ付ける（80 番は HTTPS への転送のみ）
    port80, port443 = https.split("listen 443", 1)
    assert "Strict-Transport-Security" not in port80
    assert "Strict-Transport-Security" in port443
    for name in ("http.conf", "common.inc", "ca.inc"):
        assert "Strict-Transport-Security" not in read(name), name


def test_common_headers():
    common = read("common.inc")
    for header in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"):
        assert re.search(rf"^add_header {header} .+ always;$", common, re.M), header
    assert re.search(r"^add_header Content-Security-Policy \$ncm_csp always;$", common, re.M)
    # CSP の map は HTTP / HTTPS の両方で読み込む
    for name in ("http.conf", "https.conf"):
        assert "include /etc/nginx/netconfig/csp.inc;" in read(name), name


def test_no_add_header_inside_common_locations():
    """location の中で add_header を使うと、server のヘッダー（CSP・HSTS など）がその location で付かなくなる"""
    common = read("common.inc")
    for body in re.findall(r"location[^{]*\{([^}]*)\}", common):
        assert "add_header" not in body, body


def test_app_csp_is_strict():
    values = csp_values()
    assert set(values) == {"default"}  # /docs（Swagger UI）用の緩い CSP は無くした（#39）
    d = directives(values["default"])
    assert d["default-src"] == ["'self'"]
    assert d["script-src"] == ["'self'"]  # インライン・eval・外部のスクリプトは許可しない
    assert d["style-src"] == ["'self'", "'unsafe-inline'"]  # xterm.js と印刷用ウィンドウのため
    assert d["img-src"] == ["'self'", "data:"]  # 構成図の書き出し・印刷のため
    assert d["font-src"] == ["'self'"]  # Web フォントはビルドに含めている（外部から読まない）
    assert d["connect-src"] == ["'self'"]
    assert d["object-src"] == ["'none'"]
    assert d["frame-ancestors"] == ["'none'"]
    assert d["base-uri"] == ["'self'"]
    assert "*" not in values["default"]
    assert "http" not in values["default"]  # 外部のドメインを許可しない


def test_docs_are_not_proxied_and_no_cdn_is_allowed():
    """#39: /docs・/openapi.json を backend へ中継しない（ログインなしで見られ、Swagger UI は CDN のスクリプトを読むため）。
    どの CSP も外部のスクリプト（cdn.jsdelivr.net など）とインラインのスクリプトを許さない"""
    common = read("common.inc")
    for loc in re.findall(r"location\s+([^{]*)\{", common):
        assert "docs" not in loc and "openapi" not in loc, loc
    # backend へ中継するのは /api/ だけ
    assert re.findall(r"location\s+([^{]*?)\s*\{[^}]*proxy_pass", common) == ["/api/"]
    for name, value in csp_values().items():
        d = directives(value)
        assert d["script-src"] == ["'self'"], name
        assert "cdn.jsdelivr.net" not in value and "https://" not in value, name


def test_index_html_has_no_external_resources():
    """index.html は外部（Google Fonts など）から読み込まない（閉じたネットワークでも表示を変えず、CSP を 'self' に保つ）"""
    html = (NGINX.parent / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"""(href|src)=["']https?://""", html)
