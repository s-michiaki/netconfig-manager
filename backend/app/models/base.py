from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# モデルを登録するためにインポート
from app.models.device import Device, ConfigSnapshot, CollectLog, Schedule  # noqa: F401, E402
