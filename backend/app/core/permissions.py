"""ロールベースアクセス制御（RBAC）

ロールと権限の対応はこのファイルだけで定義する。割り当てを変えたい場合は ROLE_PERMISSIONS を編集する。
フロントエンドは /api/auth/me が返す permissions を見てボタン等の表示を切り替える。
"""

from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"  # すべての操作（ユーザー・機器・スケジュールの管理を含む）
    OPERATOR = "operator"  # 閲覧 + コンフィグ収集 + SSHターミナル + 構成図の編集
    VIEWER = "viewer"  # 閲覧のみ


class Perm(str, Enum):
    DEVICE_READ = "device:read"
    DEVICE_WRITE = "device:write"  # 機器の登録・編集・削除（認証情報を扱うため admin のみ）
    CONFIG_READ = "config:read"  # 履歴・差分・コンフィグ内容の閲覧
    COLLECT = "collect:run"  # 収集の実行・タスク状態の確認
    TERMINAL = "terminal:use"  # SSHターミナル（機器を直接操作できる）
    SCHEDULE_READ = "schedule:read"
    SCHEDULE_WRITE = "schedule:write"
    USER_ADMIN = "user:admin"  # ユーザー管理
    TOPOLOGY_READ = "topology:read"  # 構成図の閲覧
    TOPOLOGY_WRITE = "topology:write"  # 構成図の作成・編集・削除（認証情報は扱わないので operator も可）


_VIEWER = {Perm.DEVICE_READ, Perm.CONFIG_READ, Perm.SCHEDULE_READ, Perm.TOPOLOGY_READ}
_OPERATOR = _VIEWER | {Perm.COLLECT, Perm.TERMINAL, Perm.TOPOLOGY_WRITE}
_ADMIN = set(Perm)

ROLE_PERMISSIONS: dict[Role, frozenset[Perm]] = {
    Role.VIEWER: frozenset(_VIEWER),
    Role.OPERATOR: frozenset(_OPERATOR),
    Role.ADMIN: frozenset(_ADMIN),
}

ROLE_LABELS = {Role.ADMIN: "管理者", Role.OPERATOR: "オペレーター", Role.VIEWER: "閲覧者"}


def permissions_for(role: str) -> frozenset[Perm]:
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()  # 未知のロールは何もできない


def has_permission(role: str, perm: Perm) -> bool:
    return perm in permissions_for(role)
