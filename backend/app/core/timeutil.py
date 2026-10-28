from datetime import datetime, timezone


def utcnow() -> datetime:
    """DBの DateTime(タイムゾーン無し) カラムに保存するための UTC 現在時刻。

    datetime.utcnow() は Python 3.12 で非推奨のため置き換え。
    既存テーブルのスキーマを変えないよう、naive な UTC として扱う。
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
