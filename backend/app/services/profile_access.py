"""認証情報プロファイルを誰が編集・使用できるか

- 管理（manage）: 所有者と、「管理を任せたユーザーグループ」のメンバー。編集・削除・共有範囲の変更ができる
- 使用（use）   : 管理できる人と、「使用を許可したユーザーグループ」のメンバー。
                  機器への割り当てと、そのプロファイルを使う機器の接続先（ホスト・ポート・踏み台）の変更ができる

接続先の変更も「使用」に含めるのは、接続先を自分の用意したサーバーに書き換えると、次の接続でパスワードが
そこへ送られるため（使用できる = パスワードを取り出せる、に近い）。
どちらも機器の編集権限（DEVICE_WRITE = 管理者）が前提。オペレーターの収集・ターミナル接続はこの制限の対象外。
"""
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import CredentialProfile, CredentialProfileAccess
from app.models.notification import UserGroupMember
from app.models.user import User

MANAGE, USE = "manage", "use"
DENY_MANAGE = "この認証情報プロファイルを編集・削除できるのは、所有者と、管理を任せたユーザーグループのメンバーだけです"


@dataclass
class Access:
    user_id: str
    group_ids: set[str] = field(default_factory=set)  # 自分が所属するユーザーグループ
    shares: dict[str, dict[str, set[str]]] = field(default_factory=dict)  # profile_id → {manage: {group}, use: {group}}

    def groups(self, profile_id: str, access: str) -> set[str]:
        return self.shares.get(profile_id, {}).get(access, set())

    def can_manage(self, p: CredentialProfile) -> bool:
        return p.owner_id == self.user_id or bool(self.group_ids & self.groups(p.id, MANAGE))

    def can_use(self, p: CredentialProfile) -> bool:
        return self.can_manage(p) or bool(self.group_ids & self.groups(p.id, USE))


async def load(db: AsyncSession, user: User) -> Access:
    a = Access(user_id=user.id)
    a.group_ids = set((await db.execute(
        select(UserGroupMember.group_id).where(UserGroupMember.user_id == user.id))).scalars())
    for row in (await db.execute(select(CredentialProfileAccess))).scalars():
        a.shares.setdefault(row.profile_id, {}).setdefault(row.access, set()).add(row.group_id)
    return a


def deny_use(name: str) -> str:
    return (f"認証情報プロファイル「{name}」を使用できません（機器への割り当てと、このプロファイルを使う機器の"
            "接続先の変更ができるのは、所有者と、使用を許可されたユーザーグループのメンバーだけです）")
