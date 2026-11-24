"""基準の世代（ベースライン）と最新のコンフィグとの「ずれ」の計算

基準 → 最新の追加・削除の行数を config_baselines に保存する。計算するのは
  (a) 基準を指定したとき（API）  (b) 収集で世代が増えたとき（worker）
Git の読み取りは同期処理なので、呼び出し側はスレッドで実行する（API は run_in_threadpool、worker は asyncio.to_thread）。
"""
import logging
from dataclasses import dataclass

from app.core.timeutil import utcnow
from app.models.device import ConfigBaseline
from app.services.config_service import count_changes, get_config_content, get_config_version, head_commit_hash

logger = logging.getLogger(__name__)


@dataclass
class Drift:
    added: int
    removed: int
    latest_hash: str  # 比べた相手の世代（40 桁）

    @property
    def total(self) -> int:
        return self.added + self.removed


def compute_drift(device_id: str, baseline_hash: str) -> Drift | None:
    """基準（完全なハッシュ）と最新の本文を比べる。どちらかを読めなければ None。基準が最新そのものなら 0 行"""
    latest = get_config_version(device_id)
    if latest is None:
        return None
    if latest["full_hash"] == baseline_hash:
        return Drift(0, 0, baseline_hash)
    base = get_config_content(device_id, baseline_hash)
    if base is None:
        return None
    added, removed = count_changes(base, latest["content"])
    return Drift(added, removed, latest["full_hash"])


def compute_drift_stable(device_id: str, baseline_hash: str) -> Drift | None:
    """compute_drift の結果が、保存の直前にも最新（HEAD）のままか確かめ、違えば 1 回だけ計算し直す。
    計算している間に収集で世代が増えても、古い最新との差を保存しないため"""
    drift = compute_drift(device_id, baseline_hash)
    if drift is not None and head_commit_hash(device_id) != drift.latest_hash:
        drift = compute_drift(device_id, baseline_hash)
    return drift


def apply_drift(row: ConfigBaseline, drift: Drift) -> None:
    row.drift_added, row.drift_removed = drift.added, drift.removed
    row.latest_hash = drift.latest_hash
    row.checked_at = utcnow()


def drift_total(row: ConfigBaseline) -> int:
    return (row.drift_added or 0) + (row.drift_removed or 0)


def is_unknown(row: ConfigBaseline) -> bool:
    """ずれが未計算（計算できなかった・まだ計算していない）"""
    return row.drift_added is None

