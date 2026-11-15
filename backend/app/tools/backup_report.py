"""バックアップ（scripts/backup.sh）の結果をアプリに伝える

backup.sh・setup.sh がホストから backend コンテナで実行する（画面「システム状態」の「バックアップ」と、
異常の通知に使う）。記録は Redis（最後の結果）とアクティビティ（履歴）に残す:

    podman exec <backend> python -m app.tools.backup_report result --status ok --file netconfig-backup-….tar.gz \\
        --size 12345 --seconds 8 --dir /var/backups/netconfig-manager --copy ok --copy-dir /mnt/nas/netconfig --post none
    podman exec <backend> python -m app.tools.backup_report schedule on --calendar "*-*-* 03:15:00"

通知はここでは送らない（API のウォッチドッグが状態の変化を見て送る。二重に通知しないため）
"""
import argparse
import asyncio
import sys

from app.core.timeutil import utcnow
from app.services import system
from app.services.activity import record as record_activity

OFFSITE = ("none", "ok", "failed")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m app.tools.backup_report")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("result", help="バックアップの結果")
    r.add_argument("--status", choices=("ok", "failed"), required=True)
    r.add_argument("--file", default="")
    r.add_argument("--size", type=int, default=0)
    r.add_argument("--seconds", type=int, default=0)
    r.add_argument("--dir", default="")
    r.add_argument("--copy", choices=OFFSITE, default="none")
    r.add_argument("--copy-dir", default="")
    r.add_argument("--post", choices=OFFSITE, default="none")
    r.add_argument("--message", default="")
    s = sub.add_parser("schedule", help="定期バックアップ（systemd タイマー）の登録状況")
    s.add_argument("state", choices=("on", "off"))
    s.add_argument("--calendar", default="")
    return p.parse_args(argv)


def describe(result: dict) -> tuple[str, str]:
    """（アクティビティの種類, 文）"""
    where = f"（{result['dir']}）" if result.get("dir") else ""
    if result["status"] != "ok":
        reason = result.get("message") or "原因はサーバーのログを確認してください"
        return "backup.failed", f"バックアップに失敗しました{where}: {reason}"
    text = f"バックアップを作成しました: {result.get('file')}{where}"
    if result.get("copy") == "ok":
        text += f"。外部へコピーしました（{result.get('copy_dir')}）"
    if "failed" in (result.get("copy"), result.get("post")):
        return "backup.offsite_failed", f"{text}。ただし外部への保管に失敗しました: {result.get('message')}"
    return "backup.completed", text


async def report_result(args: argparse.Namespace) -> str:
    from app.core.database import AsyncSessionLocal

    result = {"at": utcnow().isoformat(), "status": args.status, "file": args.file[:200], "size": args.size,
              "seconds": args.seconds, "dir": args.dir[:500], "copy": args.copy, "copy_dir": args.copy_dir[:500],
              "post": args.post, "message": args.message[:500]}
    await system.record_backup_result(result)
    event, text = describe(result)
    async with AsyncSessionLocal() as db:
        record_activity(db, event, text, detail={k: v for k, v in result.items() if k != "at"})
        await db.commit()
    return text


async def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.command == "schedule":
        await system.record_backup_schedule(args.state == "on", args.calendar or None, utcnow())
        print(f"定期バックアップの登録状況を記録しました（{args.state}）")
    else:
        print(await report_result(args))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
