"""ファイル出力の共通処理（監査ログ・アクティビティログの CSV、コンフィグのダウンロードのファイル名）"""
import csv
import io
import re
import unicodedata
from datetime import datetime
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi.responses import Response

from app.core.config import settings

MAX_EXPORT_ROWS = 100_000  # CSV に出力する最大件数


def csv_cell(v) -> str:
    """表計算ソフトで数式として解釈されないようにする（CSV インジェクション対策）"""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "はい" if v else "いいえ"
    if isinstance(v, datetime):
        return v.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo(settings.TIMEZONE)).strftime("%Y-%m-%d %H:%M:%S")
    text = str(v)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def csv_response(header: list[str], rows: list[list], filename: str) -> Response:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow([csv_cell(v) for v in r])
    # Excel で文字化けしないよう BOM 付き UTF-8
    return Response(
        content="\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def export_name(kind: str) -> str:
    return f"{kind}_{datetime.now(ZoneInfo(settings.TIMEZONE)).strftime('%Y%m%d-%H%M%S')}.csv"


# Windows でファイル名に使えない文字と制御文字
_UNSAFE_FILENAME = re.compile(r'[\\/:*?"<>|\x00-\x1f\x7f]')
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)", re.I)


def safe_filename(name: str, fallback: str = "file", max_length: int = 100) -> str:
    """機器名などからファイル名の一部を作る（OS で使えない文字は _ にする。日本語はそのまま）"""
    text = unicodedata.normalize("NFC", name)
    text = _UNSAFE_FILENAME.sub("_", text).strip().strip(".").strip()
    text = text[:max_length].rstrip(" .")
    if not text:
        return fallback
    if _WINDOWS_RESERVED.match(text):
        text = "_" + text
    return text


def content_disposition(filename: str) -> str:
    """ダウンロード用の Content-Disposition。日本語のファイル名は filename* に入れる

    HTTP ヘッダーは latin-1 でしか書けないため、filename には ASCII だけの名前（代わりの名前）を、
    filename* には UTF-8 をパーセント符号化した名前を入れる（今のブラウザは filename* を優先する）
    """
    filename = safe_filename(filename)
    ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    if not re.search(r"[A-Za-z0-9]", ascii_name.rsplit(".", 1)[0]):
        ascii_name = "download" + (f".{filename.rsplit('.', 1)[1]}" if "." in filename else "")
        ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", ascii_name)
    if ascii_name == filename:
        return f'attachment; filename="{filename}"'
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename, safe='')}"
