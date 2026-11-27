"""TOFU（初回の接続で鍵を信じて登録する）で新しく登録した SSH ホスト鍵の記録

core/ssh_hostkeys.py が登録のたびにためた記録（take_events）を、アクティビティログ（ssh.hostkey_added）と
監査ログ（同じ名前の操作）に残す。初回の接続・ホスト名を変えたあとの接続で中間者がいても、指紋から気づけるように。
記録は呼び出し側のトランザクションに追加する（commit は呼び出し側）
"""
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.services.activity import record
from app.services.audit import make_log

_DETAIL_KEYS = ("host", "recorded_as", "key_type", "fingerprint", "via")


def record_events(db: AsyncSession, events: list[dict], *, actor: str, ref: str | None = None,
                  user: User | None = None, ip: str | None = None) -> None:
    """actor: アクティビティログのきっかけ（ユーザー名・スケジュール名など）。user があれば監査ログはその利用者で残す"""
    for ev in events:
        detail = {k: ev[k] for k in _DETAIL_KEYS if ev.get(k)}
        if ev.get("target") == "jump":
            what = f"踏み台サーバ「{ev.get('jump_name') or ''}」"
            target_type, target_id, target_name = "jump_host", ev.get("jump_id"), ev.get("jump_name")
        else:
            what = "機器" + (f"（踏み台「{ev['via']}」経由）" if ev.get("via") else "")
            target_type, target_id, target_name = "device", ev.get("device_id"), ev.get("device_name")
        record(db, "ssh.hostkey_added",
               f"{what}の SSH ホスト鍵を新しく登録しました（{ev.get('key_type')} {ev.get('fingerprint')}）。"
               "初めての接続でなければ、機器の入れ替え・中間者の可能性があります。機器の鍵の指紋と照らし合わせてください",
               device_id=ev.get("device_id") if target_type == "device" else None,
               device_name=ev.get("device_name") if target_type == "device" else None,
               detail=detail, actor=actor, ref=ref)
        db.add(make_log("ssh.hostkey_added", user=user, username=None if user else actor[:64], ip=ip,
                        target_type=target_type, target_id=target_id, target_name=target_name, detail=detail))
