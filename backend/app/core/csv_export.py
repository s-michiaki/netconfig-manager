"""CSV 出力の共通処理（監査ログ・アクティビティログ）"""
import csv
import io
from datetime import datetime
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
