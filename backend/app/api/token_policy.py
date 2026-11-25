"""API トークンで呼べる API の一覧（ここに無いものは、トークンでは呼べない＝既定は「不可」）

方針:
- ログインのセッション（パスワード・2 段階認証を通ったもの）でしか行えないもの:
  API トークンの発行・失効、パスワード変更、2 段階認証、ユーザー管理、メールサーバー・通知の設定（送信先・Webhook の秘密を含む）、
  認証情報（機器・踏み台・認証情報プロファイル・SNMP のパスワードや鍵）を登録・変更する操作、ターミナルの記録の中身、
  外部 Git への push の実行、ターミナル・Ping の WebSocket（WebSocket の認証はログインのトークンだけを受け付ける）
- そのほかは、発行した人のいまのロールの権限の範囲で使える（require(Perm.xxx) で判定）。
  範囲が read のトークンは、さらに GET だけ・閲覧の権限（READ_ONLY_PERMS）だけ
- 新しい API を作っても、ここに足さない限りトークンでは呼べない（403「ログインして操作してください」）。
  tests/test_api_tokens.py の表（全ルート）と食い違うとテストが落ちる

キーは「メソッド 空白 パス」（パスは FastAPI のパスの書き方。/api/devices/{device_id} など）
"""
from collections.abc import Iterable

from fastapi import FastAPI, Request
from fastapi.routing import iter_route_contexts

TOKEN_ALLOWED: frozenset[str] = frozenset({
    # 自分の情報（トークンで使える権限を返す）
    "GET /api/auth/me",
    # 機器（登録・変更・CSV の一括登録は、機器の認証情報を受け取るのでログインが必要）
    "GET /api/devices/",
    "GET /api/devices/export",
    "GET /api/devices/defaults",
    "GET /api/devices/collect-status",
    "GET /api/devices/platforms",
    "GET /api/devices/{device_id}",
    "GET /api/devices/{device_id}/startup-diff",
    "DELETE /api/devices/{device_id}",
    "POST /api/devices/collect/all",
    "POST /api/devices/{device_id}/collect",
    # 機器グループ
    "GET /api/device-groups/",
    "POST /api/device-groups/",
    "PUT /api/device-groups/order",
    "PUT /api/device-groups/{group_id}",
    "DELETE /api/device-groups/{group_id}",
    "POST /api/device-groups/{group_id}/collect",
    "POST /api/device-groups/assign",
    # 踏み台・認証情報プロファイルは一覧（秘密の値は返さない）だけ
    "GET /api/jump-hosts/",
    "GET /api/credential-profiles/",
    # コンフィグ（履歴・差分・内容・検索・コメント・基準の世代・変更の確認）
    "GET /api/configs/compare",
    "GET /api/configs/{device_id}/history",
    "GET /api/configs/{device_id}/diff",
    "GET /api/configs/{device_id}/content/{commit_hash}",
    "GET /api/configs/{device_id}/download/{commit_hash}",
    "POST /api/configs/search",
    "POST /api/configs/search/export",
    "PUT /api/configs/{device_id}/comments/{commit_hash}",
    "DELETE /api/configs/{device_id}/comments/{commit_hash}",
    "GET /api/configs/baselines",
    "GET /api/configs/{device_id}/baseline",
    "PUT /api/configs/{device_id}/baseline",
    "DELETE /api/configs/{device_id}/baseline",
    "GET /api/configs/reviews",
    "PUT /api/configs/{device_id}/reviews/{commit_hash}",
    "DELETE /api/configs/{device_id}/reviews/{commit_hash}",
    "POST /api/configs/reviews/bulk",
    # スケジュール・タスクの状態
    "GET /api/schedules/",
    "POST /api/schedules/",
    "DELETE /api/schedules/{schedule_id}",
    "PATCH /api/schedules/{schedule_id}/toggle",
    "GET /api/tasks/{task_id}",
    # 構成図
    "GET /api/topology/maps",
    "POST /api/topology/maps",
    "GET /api/topology/maps/{map_id}",
    "GET /api/topology/maps/{map_id}/status",
    "POST /api/topology/device-status",
    "PUT /api/topology/maps/{map_id}",
    "DELETE /api/topology/maps/{map_id}",
    # コマンド実行（表示コマンドだけ）
    "GET /api/commands/limits",
    "GET /api/commands/check",
    "POST /api/commands/runs",
    "GET /api/commands/runs",
    "GET /api/commands/runs/{run_id}",
    "GET /api/commands/runs/{run_id}/export",
    # コンプライアンス
    "GET /api/compliance/templates",
    "GET /api/compliance/rules",
    "POST /api/compliance/rules",
    "PUT /api/compliance/rules/{rule_id}",
    "DELETE /api/compliance/rules/{rule_id}",
    "POST /api/compliance/rules/test",
    "GET /api/compliance/exceptions",
    "POST /api/compliance/exceptions",
    "DELETE /api/compliance/exceptions/{exception_id}",
    "POST /api/compliance/run",
    "GET /api/compliance/results",
    "GET /api/compliance/summary",
    # 無視する行
    "GET /api/ignore-rules/",
    "POST /api/ignore-rules/",
    "PUT /api/ignore-rules/{rule_id}",
    "DELETE /api/ignore-rules/{rule_id}",
    "POST /api/ignore-rules/preview",
    # 監査ログ（操作履歴と、ターミナルの接続の一覧まで。記録の中身・検索はログインが必要）
    "GET /api/audit/actions",
    "GET /api/audit/logs",
    "GET /api/audit/logs/export",
    "GET /api/audit/terminal-sessions",
    "GET /api/audit/terminal-sessions/export",
    # アクティビティ
    "GET /api/activity/events",
    "GET /api/activity/logs",
    "GET /api/activity/logs/export",
    # Ping監視
    "GET /api/ping/targets",
    "POST /api/ping/targets",
    "PUT /api/ping/targets/{target_id}",
    "DELETE /api/ping/targets/{target_id}",
    "GET /api/ping/monitors",
    "PUT /api/ping/monitors/{key}",
    "GET /api/ping/monitors/{key}/history",
    # システム状態（閲覧だけ）・ダッシュボード
    "GET /api/system/status",
    "GET /api/dashboard",
    # モニタリング（SNMP の設定の変更・削除は community・鍵を扱うのでログインが必要）
    "GET /api/monitoring/snmp",
    "POST /api/monitoring/snmp/{device_id}/test",
    "POST /api/monitoring/snmp/poll",
    "GET /api/monitoring/interfaces",
    "GET /api/monitoring/interfaces/top",
    "GET /api/monitoring/interfaces/{interface_id}/samples",
    "GET /api/monitoring/fw",
    "GET /api/monitoring/fw/{device_id}/rules",
    "POST /api/monitoring/fw/{device_id}/collect",
    "GET /api/monitoring/fw/{device_id}/raw",
})

# 範囲が read のトークンで呼べるメソッド（副作用の無いもの）
READ_METHODS = frozenset({"GET", "HEAD"})


def route_keys(app: FastAPI) -> dict[tuple[str, object], set[str]]:
    """（メソッド, エンドポイントの関数）→ そのルートの「メソッド パス」の集まり。テストでも全ルートの列挙に使う"""
    out: dict[tuple[str, object], set[str]] = {}
    for rc in iter_route_contexts(app.routes):
        if rc.endpoint is None or not rc.methods:
            continue
        for m in rc.methods:
            out.setdefault((m, rc.endpoint), set()).add(f"{m} {rc.path}")
    return out


def _allowed_set(keys: dict[tuple[str, object], set[str]], allowed: Iterable[str]) -> frozenset[tuple[str, object]]:
    allowed = set(allowed)
    # 同じ関数が複数のパスで使われているときは、すべてが許可されているときだけ許可する（安全側）
    return frozenset(k for k, paths in keys.items() if paths and paths <= allowed)


_cache: dict[int, frozenset[tuple[str, object]]] = {}
_perm_cache: dict[int, frozenset] = {}


def _required_perms(dependant) -> set:
    out = set()
    for d in dependant.dependencies:
        perm = getattr(d.call, "perm", None)
        if perm is not None:
            out.add(perm)
        out |= _required_perms(d)
    return out


def token_route_perms(app: FastAPI) -> frozenset:
    """トークンで呼べる API（TOKEN_ALLOWED）が要求する権限の集まり。/me がトークンで実際に使える権限を返すのに使う"""
    perms = _perm_cache.get(id(app))
    if perms is None:
        found: set = set()
        for rc in iter_route_contexts(app.routes):
            if rc.endpoint is None or not rc.methods or not hasattr(rc, "dependant"):
                continue
            if any(f"{m} {rc.path}" in TOKEN_ALLOWED for m in rc.methods):
                found |= _required_perms(rc.dependant)
        perms = _perm_cache[id(app)] = frozenset(found)
    return perms


def token_allowed(request: Request) -> bool:
    """このリクエスト（ルートとメソッド）を API トークンで呼んでよいか"""
    endpoint = request.scope.get("endpoint")
    if endpoint is None:
        return False
    app = request.app
    allowed = _cache.get(id(app))
    if allowed is None:
        allowed = _cache[id(app)] = _allowed_set(route_keys(app), TOKEN_ALLOWED)
    return (request.method, endpoint) in allowed
