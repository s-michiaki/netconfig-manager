"""機器パスワード等をDBに暗号化して保存するための型"""
from cryptography.fernet import Fernet
from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

from app.core.config import settings

_PREFIX = "enc:"
_fernet = Fernet(settings.DEVICE_ENCRYPTION_KEY.encode())


def encrypt(value: str) -> str:
    return _PREFIX + _fernet.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    if not is_encrypted(value):
        # 旧バージョンで平文保存された値（起動時に暗号化へ移行される）
        return value
    return _fernet.decrypt(value[len(_PREFIX):].encode()).decode()


def is_encrypted(value: str) -> bool:
    return value.startswith(_PREFIX)


class EncryptedString(TypeDecorator):
    """書き込み時に Fernet で暗号化、読み込み時に復号する文字列カラム"""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return encrypt(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return decrypt(value)
