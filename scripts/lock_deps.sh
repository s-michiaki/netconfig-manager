#!/usr/bin/env bash
# backend の依存パッケージのロックファイル（全部の版を固定し、ハッシュを付けたもの）を生成する
#   backend/requirements.in      → backend/requirements.txt      （本番。Dockerfile が --require-hashes で入れる）
#   backend/requirements-dev.in  → backend/requirements-dev.txt  （開発・テスト。本番の依存も含み、本番と同じ版にそろえる）
#
# 使い方（リポジトリのどこからでも実行できる）:
#   bash scripts/lock_deps.sh                 .in の変更をロックに反映する（変えていないパッケージの版はそのまま）
#   bash scripts/lock_deps.sh -P パッケージ名  そのパッケージだけ新しい版に上げる（間接依存の脆弱性対応など。複数指定可）
#   bash scripts/lock_deps.sh --upgrade       .in で == 指定していない間接依存をすべて新しい版に上げる
#   bash scripts/lock_deps.sh --check         .in とロックが合っているかを確かめる（ファイルは変えない。CI で使う）
#
# 必要なもの: uv（pip install uv==0.11.32）。本番のコンテナ（python:3.12-slim）と同じ Python 3.12 向けに、
# OS を問わず使える形（--universal）で解決するので、手元の Python の版や OS（Windows でも）は問わない
set -euo pipefail

UV_VERSION="0.11.32"  # CI と同じ版（版が違うと出力の書式が変わることがある）
BACKEND="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && pwd)"
FLAGS=(--universal --python-version 3.12 --generate-hashes --quiet
       --custom-compile-command "bash scripts/lock_deps.sh")

if ! command -v uv >/dev/null 2>&1; then
    echo "uv が見つかりません。pip install uv==$UV_VERSION で入れてください" >&2
    exit 1
fi
current="$(uv --version | awk '{print $2}')"
if [ "$current" != "$UV_VERSION" ]; then
    echo "注意: uv の版が CI（$UV_VERSION）と違います（$current）。書式の違いで --check が失敗することがあります" >&2
fi

# $1 のディレクトリにある .in からロックを作る（既存のロックの版を優先する）。残りの引数は uv にそのまま渡す
compile() {
    local dir="$1"
    shift
    (
        cd "$dir"
        uv pip compile requirements.in -o requirements.txt "${FLAGS[@]}" "$@"
        # 開発用は本番のロックを制約にして、本番と同じ版にする
        uv pip compile requirements-dev.in -c requirements.txt -o requirements-dev.txt "${FLAGS[@]}" "$@"
    )
}

if [ "${1:-}" = "--check" ]; then
    work="$(mktemp -d)"
    trap 'rm -rf -- "$work"' EXIT
    cp "$BACKEND"/requirements.in "$BACKEND"/requirements-dev.in \
       "$BACKEND"/requirements.txt "$BACKEND"/requirements-dev.txt "$work"/
    # コピーしたロックからハッシュを消して版だけを残す（uv は既存のロックのハッシュをそのまま使うため、
    # 消さないと手で書き換えたハッシュを見逃す）。ハッシュは PyPI の値で付け直され、コミット済みのものと比べられる
    for f in "$work"/requirements.txt "$work"/requirements-dev.txt; do
        sed -i -e '/^[[:space:]]*--hash=/d' -e 's/ \\$//' "$f"
    done
    compile "$work"
    if diff -u "$BACKEND/requirements.txt" "$work/requirements.txt" \
       && diff -u "$BACKEND/requirements-dev.txt" "$work/requirements-dev.txt"; then
        echo "ロックファイルは requirements*.in と合っています"
    else
        echo "ロックファイルが requirements*.in と合っていません。bash scripts/lock_deps.sh で生成し直してコミットしてください" >&2
        exit 1
    fi
    exit 0
fi

compile "$BACKEND" "$@"
echo "生成しました: backend/requirements.txt・backend/requirements-dev.txt（差分を確認してコミットしてください）"
