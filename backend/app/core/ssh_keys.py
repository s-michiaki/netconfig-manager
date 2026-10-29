"""SSH 秘密鍵の読み込み（踏み台・機器で共通）"""
import io

import paramiko

MAX_PRIVATE_KEY_LENGTH = 16 * 1024

_KEY_CLASSES: list[type[paramiko.PKey]] = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
if hasattr(paramiko, "DSSKey"):  # Paramiko 4 で削除予定
    _KEY_CLASSES.append(paramiko.DSSKey)


class PrivateKeyError(ValueError):
    pass


def normalize_private_key(text: str) -> str:
    return text.replace("\r\n", "\n").strip() + "\n"


def load_private_key(text: str, passphrase: str | None = None) -> paramiko.PKey:
    """OpenSSH / PEM 形式の秘密鍵文字列を読み込む（RSA / ECDSA / Ed25519）"""
    text = normalize_private_key(text)
    if "PuTTY-User-Key-File" in text:
        raise PrivateKeyError("PuTTY形式(.ppk)の鍵は使えません。PuTTYgen で OpenSSH 形式に変換してください")
    if "PRIVATE KEY" not in text:
        raise PrivateKeyError("秘密鍵の形式を認識できません（-----BEGIN ... PRIVATE KEY----- で始まる鍵を貼り付けてください）")

    needs_passphrase = False
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            needs_passphrase = True
        except (paramiko.SSHException, ValueError, TypeError, IndexError):
            continue
    if needs_passphrase and not passphrase:
        raise PrivateKeyError("この秘密鍵はパスフレーズで保護されています。パスフレーズを入力してください")
    raise PrivateKeyError("秘密鍵を読み込めませんでした（形式が不正、またはパスフレーズが違います）")


def key_summary(pkey: paramiko.PKey) -> str:
    """画面表示用（例: ssh-ed25519 SHA256:xxxx）"""
    return f"{pkey.get_name()} {pkey.fingerprint}" if hasattr(pkey, "fingerprint") else pkey.get_name()
