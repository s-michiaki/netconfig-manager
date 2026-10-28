"""パスワードハッシュとJWT"""
import hashlib
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.core.config import settings

# bcrypt は72バイトを超える入力を扱えないため、API側でこの長さに制限する
MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    pw = password.encode()
    if len(pw) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(pw, hashed.encode())
    except ValueError:
        return False


# ユーザーが存在しない場合も同じ時間をかけて照合し、ユーザー名の存在を推測されにくくする
DUMMY_HASH = hash_password("dummy-password-for-timing")


def password_fingerprint(hashed_password: str) -> str:
    """パスワード変更・リセットで既存トークンを無効にするための指紋（ハッシュのハッシュ）"""
    return hashlib.sha256(hashed_password.encode()).hexdigest()[:16]


def create_access_token(user_id: str, hashed_password: str) -> str:
    """ロールはトークンに入れず、リクエストごとにDBから読む（ロール変更を即時反映するため）"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "pwv": password_fingerprint(hashed_password),
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.PyJWTError:
        return None
