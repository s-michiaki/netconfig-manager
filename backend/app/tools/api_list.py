"""API の一覧を表示する（本番で /docs を出さないため、API トークンでスクリプトを書くときはこれで調べる）

ホストから backend のコンテナで実行する（DB・Redis には接続しない）:

    sudo podman exec <backend> python -m app.tools.api_list            # メソッド・パス・トークンで呼べるか・概要
    sudo podman exec <backend> python -m app.tools.api_list --json > openapi.json   # OpenAPI のスキーマ（全項目）

<backend> は `sudo podman ps --filter label=com.docker.compose.service=backend -q` で分かる
"""
import argparse
import json
import sys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="python -m app.tools.api_list")
    p.add_argument("--json", action="store_true", help="OpenAPI のスキーマ（JSON）をそのまま出す")
    args = p.parse_args(argv)
    from app.core.api_docs import api_rows
    from app.main import app

    if args.json:
        print(json.dumps(app.openapi(), ensure_ascii=False, indent=2))
        return 0
    for r in api_rows(app):
        print(f"{r['method']:<7}{r['path']:<60}{'token' if r['token'] else '-':<7}{r['summary']}")
    print("（token: API トークンで呼べる。- はログインのセッションだけ、またはログイン不要）", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
