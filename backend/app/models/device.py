import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import EncryptedString, EncryptedText
from app.core.timeutil import utcnow
from app.models.base import Base


class JumpHost(Base):
    """踏み台サーバ（1段のみ）。機器は jump_host_id でこれを経由して接続する"""

    __tablename__ = "jump_hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    # 認証はパスワード・秘密鍵のどちらか、または両方（すべて暗号化して保存）
    password: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    private_key: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    key_passphrase: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    devices: Mapped[list["Device"]] = relationship("Device", back_populates="jump_host")


class CredentialProfile(Base):
    """認証情報プロファイル。同じアカウントを使う複数の機器で共有する（パスワードの変更が 1 か所で済む）

    機器が credential_profile_id でこれを選ぶと、機器側の認証情報は使わず、こちらの値で接続する
    （解決は services/connection.py の effective_credentials の 1 か所）
    """

    __tablename__ = "credential_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    # 認証はパスワード・秘密鍵のどちらか、または両方（すべて機器と同じ方法で暗号化して保存）
    password: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    private_key: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    key_passphrase: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    enable_secret: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    # 所有者（作成した人）。編集・削除・共有範囲の変更ができる。ユーザーを削除すると NULL（管理者が引き継ぐ）
    owner_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", name="fk_credential_profiles_owner_id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class CredentialProfileAccess(Base):
    """認証情報プロファイルの共有範囲（ユーザーグループ単位）

    access = "manage": 所有者と同じく編集・削除・共有範囲の変更ができる（使用もできる）
    access = "use"   : 機器への割り当てと、そのプロファイルを使う機器の接続先の変更ができる
    """

    __tablename__ = "credential_profile_access"

    profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("credential_profiles.id", name="fk_cpa_profile_id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_groups.id", name="fk_cpa_group_id", ondelete="CASCADE"), primary_key=True
    )
    access: Mapped[str] = mapped_column(String(8), nullable=False)  # manage / use


class DeviceGroup(Base):
    """機器のグループ（拠点・用途など）。機器は1つのグループにだけ所属できる（未所属も可）"""

    __tablename__ = "device_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    color: Mapped[str | None] = mapped_column(String(7), nullable=True)  # 画面の見出しの色（#rrggbb）
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")  # 表示順（小さい順）
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)  # cisco_ios, juniper_junos, etc.
    port: Mapped[int] = mapped_column(Integer, default=22)
    # 認証情報プロファイルを使う機器では username・password・private_key・key_passphrase・enable_secret は NULL
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 認証はパスワード・SSH秘密鍵のどちらか、または両方。Fernet で暗号化して保存（DEVICE_ENCRYPTION_KEY）
    password: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    private_key: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    key_passphrase: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    enable_secret: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # 応答待ち時間（秒）。NULL なら既定値（SSH_READ_TIMEOUT）。応答の遅い機器向け
    read_timeout: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 経由する踏み台（NULL なら直接接続）
    jump_host_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("jump_hosts.id", name="fk_devices_jump_host_id"), nullable=True
    )
    # 所属グループ（NULL なら未分類）。グループを削除すると未分類に戻る
    group_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("device_groups.id", name="fk_devices_group_id"), nullable=True
    )
    # 認証情報プロファイル（NULL ならこの機器だけの認証情報を使う）。使用中のプロファイルは削除できない
    credential_profile_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("credential_profiles.id", name="fk_devices_credential_profile_id"), nullable=True
    )
    # 機器台帳（収集のときに show version などから自動で読み取る。services/inventory.py）
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reported_hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)  # 機器に設定されているホスト名
    inventory_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # 最後に読み取れた日時
    # 保存し忘れの検出（startup-config と running-config の不一致。services/startup_check.py）
    # startup_state: synced（一致）/ unsaved（保存されていない変更がある）/ unknown（比べられなかった）/ NULL（対象外・無効）
    startup_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    startup_added: Mapped[int | None] = mapped_column(Integer, nullable=True)  # running にだけある行数
    startup_removed: Mapped[int | None] = mapped_column(Integer, nullable=True)  # startup にだけある行数
    # unified diff（コンフィグの中身を含むので、API は GET /api/devices/{id}/startup-diff だけで返す）
    startup_diff: Mapped[str | None] = mapped_column(Text, nullable=True, deferred=True)  # 一覧では読み込まない
    startup_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    jump_host: Mapped["JumpHost | None"] = relationship("JumpHost", back_populates="devices")
    credential_profile: Mapped["CredentialProfile | None"] = relationship("CredentialProfile")
    config_snapshots: Mapped[list["ConfigSnapshot"]] = relationship(
        "ConfigSnapshot", back_populates="device", cascade="all, delete-orphan"
    )
    collect_logs: Mapped[list["CollectLog"]] = relationship(
        "CollectLog", back_populates="device", cascade="all, delete-orphan"
    )
    config_comments: Mapped[list["ConfigComment"]] = relationship(
        "ConfigComment", back_populates="device", cascade="all, delete-orphan"
    )
    config_reviews: Mapped[list["ConfigReview"]] = relationship(
        "ConfigReview", back_populates="device", cascade="all, delete-orphan"
    )
    config_baseline: Mapped["ConfigBaseline | None"] = relationship(
        "ConfigBaseline", back_populates="device", cascade="all, delete-orphan", uselist=False
    )
    ignore_rules: Mapped[list["ConfigIgnoreRule"]] = relationship(  # noqa: F821 - models/ignore_rule.py
        "ConfigIgnoreRule", back_populates="device", cascade="all, delete-orphan"
    )


class ConfigSnapshot(Base):
    """Gitコミットハッシュとメタデータを管理する世代テーブル"""

    __tablename__ = "config_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), nullable=False)
    commit_hash: Mapped[str] = mapped_column(String(40), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    lines_added: Mapped[int] = mapped_column(Integer, default=0)
    lines_removed: Mapped[int] = mapped_column(Integer, default=0)
    triggered_by: Mapped[str] = mapped_column(String(64), default="manual")  # schedule / manual

    device: Mapped["Device"] = relationship("Device", back_populates="config_snapshots")


class ConfigComment(Base):
    """世代（Git のコミット）に付ける作業内容のメモ。1 世代に 1 件

    config_snapshots の行が無い世代（直接保存したものなど）もあるため、別のテーブルで Git のコミットに結び付ける。
    書いた人は名前で持つ（ユーザーを削除しても残す。監査ログと同じ考え方）
    """

    __tablename__ = "config_comments"
    __table_args__ = (UniqueConstraint("device_id", "commit_hash", name="uq_config_comments_device_commit"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_config_comments_device_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    commit_hash: Mapped[str] = mapped_column(String(40), nullable=False)  # 完全な 40 桁
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    device: Mapped["Device"] = relationship("Device", back_populates="config_comments")


class ConfigReview(Base):
    """変更（世代）の確認の状態。確認済み（confirmed）か想定外（unexpected）。付いていない世代は「未確認」

    config_comments と同じく Git のコミットに結び付ける。確認した人は名前で持つ（ユーザーを削除しても残す）
    """

    __tablename__ = "config_reviews"
    __table_args__ = (UniqueConstraint("device_id", "commit_hash", name="uq_config_reviews_device_commit"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_config_reviews_device_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    commit_hash: Mapped[str] = mapped_column(String(40), nullable=False)  # 完全な 40 桁
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # confirmed / unexpected
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    device: Mapped["Device"] = relationship("Device", back_populates="config_reviews")


class ConfigBaseline(Base):
    """機器ごとの基準の世代（承認済みの状態）と、最新のコンフィグとのずれ。1 機器に 1 件

    drift_added / drift_removed は基準 → 最新の追加・削除の行数。基準を指定したとき・収集で世代が増えたときに計算し、
    latest_hash に「どの世代と比べたか」を残す（画面は保存した値を読むだけで、Git を読まない）。
    指定した人は名前で持つ（ユーザーを削除しても残す）
    """

    __tablename__ = "config_baselines"

    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_config_baselines_device_id", ondelete="CASCADE"), primary_key=True
    )
    commit_hash: Mapped[str] = mapped_column(String(40), nullable=False)  # 完全な 40 桁
    note: Mapped[str | None] = mapped_column(String(200), nullable=True)
    set_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    set_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    set_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    drift_added: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None は未計算
    drift_removed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latest_hash: Mapped[str | None] = mapped_column(String(40), nullable=True)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    device: Mapped["Device"] = relationship("Device", back_populates="config_baseline")


class CollectLog(Base):
    __tablename__ = "collect_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), nullable=False)
    status: Mapped[str] = mapped_column(Enum("success", "failed", name="collect_status"), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    device: Mapped["Device"] = relationship("Device", back_populates="collect_logs")


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), default="all")  # "all" / "group:<id>" / device_id
    # collect: コンフィグ収集 / compliance: 収集済みのコンフィグをコンプライアンスチェック（収集はしない）
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="collect", server_default="collect")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
