"""ワンタイムパスワード（TOTP。RFC 6238）と、2 段階認証の予備コード

認証アプリ（Google Authenticator・Microsoft Authenticator など）と同じ方式: SHA-1・6 桁・30 秒。
時計のずれに備えて前後 1 つ（±30 秒）まで受け付け、同じコード（同じ時間枠）の再利用は拒否する（呼び出し側が
最後に使った時間枠を保存して渡す）
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30
WINDOW = 1  # 前後に受け付ける時間枠の数
RECOVERY_COUNT = 10


def new_secret() -> str:
    """160 bit の秘密鍵（Base32。認証アプリに手で入力する場合もこの文字列）"""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // PERIOD)


def code_at(secret: str, step: int) -> str:
    return _hotp(secret, step)


def verify(secret: str, code: str, last_step: int | None = None, now: float | None = None) -> int | None:
    """コードが正しければその時間枠を返す（保存して、次回 last_step として渡す）。誤り・使用済みなら None"""
    code = "".join(c for c in code if c.isdigit())
    if len(code) != DIGITS:
        return None
    step = current_step(now)
    for s in range(step - WINDOW, step + WINDOW + 1):
        if last_step is not None and s <= last_step:
            continue
        if hmac.compare_digest(_hotp(secret, s), code):
            return s
    return None


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """認証アプリに読み込ませる otpauth:// の URI（QR コードにする）"""
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"


def qr_svg(uri: str) -> str:
    import segno

    # omitsize: 幅・高さの代わりに viewBox を付け、画面側の大きさに合わせて縮められるようにする
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#000", light="#fff", border=2, omitsize=True)


# ---------------------------------------------------------------- 予備コード（認証アプリを無くしたとき用。1 回ずつ使える）


def _norm(code: str) -> str:
    return "".join(c for c in code.lower() if c.isalnum())


def hash_recovery(code: str) -> str:
    return hashlib.sha256(_norm(code).encode()).hexdigest()


def new_recovery_codes() -> list[str]:
    """xxxx-xxxx（英小文字と数字。紛らわしい文字を除く）を RECOVERY_COUNT 個"""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    out = []
    for _ in range(RECOVERY_COUNT):
        s = "".join(secrets.choice(alphabet) for _ in range(8))
        out.append(f"{s[:4]}-{s[4:]}")
    return out


def looks_like_recovery(code: str) -> bool:
    n = _norm(code)
    return len(n) == 8 and not n.isdigit()
