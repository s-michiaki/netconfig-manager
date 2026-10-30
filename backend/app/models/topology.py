import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.models.base import Base

EMPTY_TOPOLOGY = '{"nodes": [], "edges": []}'


class TopologyMap(Base):
    """構成図。配置（ノード）と接続線（エッジ）は JSON でまとめて保存する

    data（物理構成）/ logical_data（論理構成） = {"nodes": [...], "edges": [...]}
    （形式は app/api/topology.py の TopologyData）
    機器ノードは device_id で devices を参照する。機器が削除された場合は読み書き時に取り除く
    """

    __tablename__ = "topology_maps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[str] = mapped_column(Text, nullable=False, default=EMPTY_TOPOLOGY)  # 物理構成
    logical_data: Mapped[str] = mapped_column(Text, nullable=False, default=EMPTY_TOPOLOGY)  # 論理構成
    # 楽観ロック。保存のたびに +1 し、他の人が先に保存した内容を上書きしないようにする
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
