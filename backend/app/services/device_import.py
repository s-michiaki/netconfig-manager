"""機器の CSV 一括登録（取り込むファイルの読み込み・解釈・検証）

画面から送られた CSV をサーバーで解釈し、1 行ずつ DeviceCreate（1 台ずつの登録と同じ規則）で確かめる。
確認（dry-run）と本登録は同じ validate() を通すので、結果は一致する。

パスワードを扱うため、次を守る:
- 結果（RowResult.public()）・エラーメッセージ・ログに、パスワードなど認証情報の値を入れない
- pydantic の ValidationError を文字列にしない（入力値が含まれる）。errors() の種類から日本語の文に置き換える
- ファイルはメモリで処理し、ディスクに保存しない
"""
import csv
import io
import unicodedata
from dataclasses import dataclass, field

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import CredentialProfile, Device, DeviceGroup, JumpHost
from app.services.config_service import PLATFORMS

MAX_IMPORT_ROWS = 500  # 1 回に取り込める行数（見出し・空行・コメント行を除く）
MAX_IMPORT_BYTES = 1024 * 1024  # 1MB（nginx の client_max_body_size に合わせる）


class ImportFormatError(ValueError):
    """ファイル全体を読めない（文字コード・見出し・行数など）。文言はそのまま画面に出す"""


# 列の見出し → 項目名。見出しは台帳 CSV（GET /api/devices/export）と同じ綴りにそろえる。
# 先頭がひな形・画面で表示する正式な見出し、続くのは受け付ける別名
COLUMNS: dict[str, tuple[str, ...]] = {
    "name": ("名前", "name"),
    "hostname": ("ホスト / IP", "ホスト", "IP", "hostname", "host"),
    "port": ("ポート", "port"),
    "group": ("グループ", "group"),
    "platform": ("機種", "platform"),
    "jump_host": ("踏み台", "jump_host"),
    "credential_profile": ("認証情報プロファイル", "credential_profile", "profile"),
    "is_active": ("有効", "active", "is_active"),
    "username": ("ユーザー名", "username"),
    "password": ("パスワード", "password"),
    "enable_secret": ("Enable パスワード", "enable_secret", "enable"),
    "read_timeout": ("応答待ち時間（秒）", "応答待ち時間", "read_timeout"),
    "description": ("説明", "description"),
}
# ユーザー名・パスワードの列は必須（認証情報プロファイルを指定した行だけ、値を空にできる）
REQUIRED = ("name", "hostname", "platform", "username", "password")
LABELS = {k: v[0] for k, v in COLUMNS.items()}  # 項目名 → エラーメッセージに出す列名

TRUE_WORDS = {"はい", "有効", "true", "yes", "y", "1", "on"}
FALSE_WORDS = {"いいえ", "無効", "false", "no", "n", "0", "off"}


def _norm(text: str) -> str:
    """見出し・機種・グループ名の比較用（全角半角・大文字小文字・空白のゆれを無視）"""
    return "".join(unicodedata.normalize("NFKC", text).casefold().split())


_HEADER_MAP = {_norm(alias): key for key, aliases in COLUMNS.items() for alias in aliases}


def decode(raw: bytes) -> tuple[str, str]:
    """UTF-8（BOM あり・なし）を先に試し、だめなら Shift_JIS（Windows の cp932）として読む"""
    if b"\x00" in raw:
        # UTF-16（Excel の「Unicode テキスト」）やバイナリのファイル
        raise ImportFormatError("文字コードを判別できません。UTF-8 または Shift_JIS の CSV で保存してください")
    try:
        return raw.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("cp932"), "shift_jis"
    except UnicodeDecodeError as e:
        raise ImportFormatError("文字コードを判別できません。UTF-8 または Shift_JIS の CSV で保存してください") from e


@dataclass
class ParsedCsv:
    columns: dict[str, int]  # 項目名 → 列の位置
    ignored_columns: list[str]
    rows: list[tuple[int, list[str]]]  # (行番号, セル)


def parse(text: str) -> ParsedCsv:
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader, None)
        while header is not None and not any(c.strip() for c in header):
            header = next(reader, None)  # 先頭の空行は飛ばす
        if header is None:
            raise ImportFormatError("ファイルが空です。1 行目に列の見出しを書いてください（ひな形を参考にしてください）")
        columns: dict[str, int] = {}
        ignored: list[str] = []
        for i, cell in enumerate(header):
            label = cell.strip()
            key = _HEADER_MAP.get(_norm(label))
            if key is None:
                if label:
                    ignored.append(label)
                continue
            if key in columns:
                raise ImportFormatError(f"列の見出し「{LABELS[key]}」が 2 つあります")
            columns[key] = i
        missing = [LABELS[k] for k in REQUIRED if k not in columns]
        if missing:
            raise ImportFormatError(
                f"必須の列がありません: {'、'.join(missing)}（1 行目は列の見出しです。ひな形を参考にしてください。"
                "台帳 CSV を使う場合は「ユーザー名」「パスワード」の列を足してください）")
        rows: list[tuple[int, list[str]]] = []
        prev = reader.line_num
        for cells in reader:
            line = prev + 1  # 行の始まりの行番号（説明の中の改行があっても物理行に合わせる）
            prev = reader.line_num
            if not any(c.strip() for c in cells):
                continue
            if cells[0].lstrip().startswith("#"):
                continue  # コメント行（ひな形の説明など）
            rows.append((line, cells))
            if len(rows) > MAX_IMPORT_ROWS:
                raise ImportFormatError(
                    f"一度に取り込めるのは {MAX_IMPORT_ROWS} 行までです。ファイルを分けてください")
    except csv.Error as e:
        raise ImportFormatError(f"CSV として読めません（{reader.line_num} 行目）") from e
    if not rows:
        raise ImportFormatError("取り込む行がありません（見出しの次の行から機器を 1 台ずつ書いてください）")
    return ParsedCsv(columns, ignored, rows)


@dataclass
class RowResult:
    line: int
    name: str
    hostname: str
    platform: str  # 表示名（分からなければ入力のまま）
    group: str | None
    jump_host: str | None
    credential_profile: str | None = None
    status: str = "ok"  # ok（登録できる） / error / skip（同じ名前の機器が既にある）
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data: dict | None = None  # 登録に使う値（認証情報を含む。画面には返さない）

    def public(self) -> dict:
        return {"line": self.line, "name": self.name, "hostname": self.hostname, "platform": self.platform,
                "group": self.group, "jump_host": self.jump_host, "credential_profile": self.credential_profile,
                "status": self.status,
                "errors": self.errors, "warnings": self.warnings}


def _platform_index() -> dict[str, str]:
    """機種の指定 → ID。ID の完全一致を優先し、次に表示名・ID のゆれ（全角半角・大文字小文字・空白）を無視して引く"""
    index: dict[str, str] = {}
    for pid, spec in PLATFORMS.items():
        index.setdefault(_norm(spec.label), pid)
    for pid in PLATFORMS:
        index[_norm(pid)] = pid  # ID が表示名と重なった場合は ID を優先する
    return index


def resolve_platform(value: str) -> str | None:
    if value in PLATFORMS:
        return value
    return _platform_index().get(_norm(value))


def _unquote(text: str) -> str:
    """台帳 CSV は = + - @ で始まる値の先頭に ' を付けて書き出す（数式にしないため）。取り込むときに外す"""
    if len(text) >= 2 and text[0] == "'" and text[1] in "=+-@":
        return text[1:]
    return text


def _parse_bool(text: str) -> bool | None:
    t = _norm(text)
    if t in TRUE_WORDS:
        return True
    if t in FALSE_WORDS:
        return False
    return None


async def _name_index(db: AsyncSession, model) -> dict[str, list[tuple[str, str]]]:
    """グループ・踏み台・認証情報プロファイルの、比較用の名前 → [(id, 名前)]（同じになる名前が複数あれば曖昧）"""
    index: dict[str, list[tuple[str, str]]] = {}
    for rid, name in (await db.execute(select(model.id, model.name))).all():
        index.setdefault(_norm(name), []).append((rid, name))
    return index


def _lookup(value: str | None, index: dict[str, list[tuple[str, str]]], label: str, key: str,
            errs: dict[str, str]) -> str | None:
    """グループ・踏み台・認証情報プロファイルの名前 → ID。見つからない・曖昧なら errs に文を足して None"""
    if not value:
        return None
    hits = index.get(_norm(value), [])
    if not hits:
        errs[key] = f"{label}「{value}」は登録されていません（先に{label}を作成してください）"
        return None
    if len(hits) > 1:
        errs[key] = f"{label}「{value}」に当てはまるものが複数あります（名前を正確に書いてください）"
        return None
    return hits[0][0]


def _pydantic_message(err: dict) -> str:
    """pydantic の検証エラーを日本語にする（入力値は含めない）"""
    t, ctx = err.get("type", ""), err.get("ctx") or {}
    if t == "string_too_short":
        return "空です"
    if t == "string_too_long":
        return f"{ctx.get('max_length')} 文字以内で入力してください"
    if t in ("int_parsing", "int_from_float", "int_type"):
        return "数字で入力してください"
    if t == "greater_than_equal":
        return f"{ctx.get('ge')} 以上で入力してください"
    if t == "less_than_equal":
        return f"{ctx.get('le')} 以下で入力してください"
    if t == "value_error":
        return str(err.get("msg", "")).removeprefix("Value error, ")
    return "値が正しくありません"


async def validate(db: AsyncSession, parsed: ParsedCsv, on_duplicate: str = "skip") -> list[RowResult]:
    """各行を確かめる。DB は読むだけで変更しない"""
    from app.api.devices import DeviceCreate  # API の入力規則をそのまま使う（循環 import を避けてここで読む）

    groups = await _name_index(db, DeviceGroup)
    jumps = await _name_index(db, JumpHost)
    profiles = await _name_index(db, CredentialProfile)
    existing = dict((await db.execute(select(Device.name, Device.hostname))).all())
    existing_fold = {n.casefold(): n for n in existing}
    hosts: dict[str, str] = {}  # ホスト / IP（小文字）→ その機器の名前
    for n, h in existing.items():
        hosts.setdefault(h.lower(), n)
    seen: dict[str, int] = {}  # このファイルの名前 → 行番号
    seen_fold: dict[str, str] = {}

    results: list[RowResult] = []
    for line, cells in parsed.rows:
        def cell(key: str, cells=cells) -> str:
            i = parsed.columns.get(key)
            return cells[i] if i is not None and i < len(cells) else ""

        name = _unquote(cell("name").strip())
        hostname = unicodedata.normalize("NFKC", cell("hostname")).strip()
        platform_in = cell("platform").strip()
        group_in = cell("group").strip() or None
        jump_in = cell("jump_host").strip() or None
        profile_in = cell("credential_profile").strip() or None
        platform_id = resolve_platform(platform_in) if platform_in else None
        row = RowResult(line=line, name=name, hostname=hostname,
                        platform=PLATFORMS[platform_id].label if platform_id else platform_in,
                        group=group_in, jump_host=jump_in, credential_profile=profile_in)
        errs: dict[str, str] = {}  # 項目名 → 文（1 列に 1 つ）

        if not platform_in:
            errs["platform"] = "空です"
        elif not platform_id:
            errs["platform"] = (f"「{platform_in}」は対応する機種にありません（機種の ID か表示名で指定します。"
                                "例: cisco_ios、Cisco IOS）")

        password = cell("password")
        if profile_in:
            # 認証情報はプロファイルのものを使う。この行のユーザー名・パスワードは使わない（保存もしない）
            if cell("username").strip() or password or cell("enable_secret"):
                row.warnings.append("認証情報プロファイルを使うため、この行のユーザー名・パスワード・"
                                    "Enable パスワードは使いません")
        elif not password:
            errs["password"] = ("空です（SSH 鍵は CSV では登録できません。パスワードを入力するか、"
                                "認証情報プロファイルを指定するか、機器を 1 台ずつ登録してください）")

        group_id = _lookup(group_in, groups, "グループ", "group", errs)
        jump_id = _lookup(jump_in, jumps, "踏み台", "jump_host", errs)
        profile_id = _lookup(profile_in, profiles, "認証情報プロファイル", "credential_profile", errs)

        active_in = cell("is_active").strip()
        is_active = True
        if active_in:
            parsed_bool = _parse_bool(active_in)
            if parsed_bool is None:
                errs["is_active"] = "「はい」か「いいえ」で入力してください"
            else:
                is_active = parsed_bool

        body: dict = {
            "name": name, "hostname": hostname, "platform": platform_id or "cisco_ios",
            "username": cell("username").strip(),
            "password": password or "x",  # 空のときのエラーは上で出したので、ほかの列の検証用に仮の値を入れる
            "enable_secret": cell("enable_secret") or None,
            "description": _unquote(cell("description").strip()) or None,
            "is_active": is_active, "group_id": group_id, "jump_host_id": jump_id,
        }
        if profile_in:
            # プロファイルが見つからない行もエラーは上で出したので、仮の ID で検証する（登録はされない）
            body.update(credential_profile_id=profile_id or "-", username=None, password=None, enable_secret=None)
        for key in ("port", "read_timeout"):
            v = unicodedata.normalize("NFKC", cell(key)).strip()
            if v:
                body[key] = v
        try:
            payload = DeviceCreate.model_validate(body)
        except ValidationError as e:
            payload = None
            for err in e.errors():
                key = str(err["loc"][0]) if err.get("loc") else ""
                if key in errs:
                    continue
                if key == "hostname" and err.get("type") == "string_pattern_mismatch":
                    errs[key] = "使えない文字があります（英数字と . : - _ のみ。IP アドレスかホスト名を書いてください）"
                else:
                    errs[key] = _pydantic_message(err)

        # 同じ名前（既存の機器・このファイルの前の行）
        if name:
            if name in seen:
                errs.setdefault("name", f"{seen[name]} 行目と名前が同じです")
            elif name in existing:
                msg = f"同じ名前の機器が既にあります（ホスト / IP: {existing[name]}）"
                if on_duplicate == "error":
                    errs.setdefault("name", msg)
                elif not errs:
                    row.status = "skip"
                    row.warnings.append(msg)
            else:
                other = existing_fold.get(name.casefold()) or seen_fold.get(name.casefold())
                if other:
                    row.warnings.append(f"「{other}」と大文字・小文字だけが違う名前です（別の機器として登録します）")
            seen.setdefault(name, line)
            seen_fold.setdefault(name.casefold(), name)

        if errs:
            row.status = "error"
            row.errors = [f"{LABELS.get(k, k)}: {m}" if k else m for k, m in errs.items()]
        elif row.status == "ok":
            other = hosts.get(hostname.lower())
            if other and other != name:
                row.warnings.append(f"「{other}」と同じホスト / IP です")
            row.data = payload.model_dump() if payload else None
        if hostname and row.status != "error":
            hosts.setdefault(hostname.lower(), name)
        results.append(row)
    return results


def template_rows() -> tuple[list[str], list[list]]:
    """ひな形 CSV の見出しと例。例のパスワードは空にして、そのまま取り込んでも登録されないようにする"""
    header = [LABELS[k] for k in ("name", "hostname", "port", "group", "platform", "jump_host",
                                  "credential_profile", "is_active", "username", "password", "enable_secret",
                                  "read_timeout", "description")]
    rows = [
        ["# # で始まる行は読み飛ばします。必須: 名前・ホスト / IP・機種・ユーザー名・パスワード"
         "（認証情報プロファイルを指定した行は、ユーザー名・パスワードを空にします）。"
         "機種は ID（cisco_ios など）か表示名（Cisco IOS など）。グループ・踏み台・認証情報プロファイルは登録済みの名前。"
         "パスワードは平文です。取り込んだらこのファイルを削除してください"] + [""] * (len(header) - 1),
        ["本社-コアSW", "192.0.2.1", 22, "", "Cisco IOS", "", "", "はい", "admin", "", "", "", "例: 本社 1F"],
        ["支店-RT", "192.0.2.2", "", "", "yamaha", "", "", "はい", "admin", "", "", 60, ""],
    ]
    return header, rows
