# 全モデルをここで読み込み、Base.metadata に登録する
# （base.py から device.py を import すると循環importになるため、ここに集約）
from app.models.base import Base
from app.models.device import CollectLog, ConfigSnapshot, Device, Schedule
from app.models.user import User

__all__ = ["Base", "CollectLog", "ConfigSnapshot", "Device", "Schedule", "User"]
