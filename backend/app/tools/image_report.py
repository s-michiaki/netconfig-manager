"""使っているコンテナのイメージの作成日時をアプリに伝える（#18）

setup.sh がイメージを取り直したあとに、ホストから backend コンテナで実行する。記録は Redis に残し、
画面「システム状態」の「コンテナのイメージ」で、古いイメージのまま動いていないかを確かめる:

    podman exec <backend> python -m app.tools.image_report \\
        --image "docker.io/library/postgres:16-alpine=2026-11-19 03:12:45.123 +0000 UTC" \\
        --pull-failed docker.io/library/redis:7-alpine

--image の作成日時は podman image inspect --format '{{.Created}}' の値をそのまま渡す
"""
import argparse
import asyncio
import sys

from app.core.timeutil import utcnow
from app.services import system


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m app.tools.image_report")
    p.add_argument("--image", action="append", default=[], help="名前=作成日時（podman image inspect の Created）")
    p.add_argument("--pull-failed", action="append", default=[], help="取り直せなかったイメージ")
    return p.parse_args(argv)


def build_report(args: argparse.Namespace) -> dict:
    images = []
    for item in args.image:
        name, _, created = item.partition("=")
        at = system.parse_image_created(created)
        images.append({"name": name.strip()[:200], "created": at.isoformat() if at else None})
    return {"reported_at": utcnow().isoformat(), "images": images,
            "pull_failed": [n.strip()[:200] for n in args.pull_failed if n.strip()]}


async def main(argv: list[str]) -> int:
    report = build_report(parse_args(argv))
    await system.record_images(report)
    print(f"イメージの情報を記録しました（{len(report['images'])} 件）")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
