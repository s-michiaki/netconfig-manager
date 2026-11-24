import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)
from redis.exceptions import RedisError
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.credential_profiles import key_info
from app.api.deps import require
from app.api.monitoring import delete_device_monitoring
from app.core.config import settings
from app.core.csv_export import csv_response, export_name
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.ssh_keys import (
    MAX_PRIVATE_KEY_LENGTH,
    PrivateKeyError,
    load_private_key,
    normalize_private_key,
)
from app.models.compliance import ComplianceException, ComplianceResult
from app.models.device import CollectLog, ConfigComment, ConfigReview, CredentialProfile, Device, DeviceGroup, JumpHost
from app.services import collect_state, device_import, inventory, login_limit, profile_access
from app.services.audit import Audit, changed_fields, get_audit
from app.services.config_service import PLATFORMS
from app.services.connection import effective_credentials
from app.services.notify import notify_profile_owner
from app.worker import collect_all_devices, collect_device_config, mark_collect_queued

router = APIRouter()

# 機器側の認証情報の項目（認証情報プロファイルを使う機器では、どれも保存しない）
CREDENTIAL_FIELDS = ("username", "password", "private_key", "key_passphrase", "enable_secret")


def _check_platform(v: str) -> str:
    if v not in PLATFORMS:
        raise ValueError("未対応のプラットフォームです")
    return v


# 対応プラットフォームは config_service.PLATFORMS で一元管理する
Platform = Annotated[str, AfterValidator(_check_platform)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Host = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[A-Za-z0-9.:_\-\[\]%]+$")
]
Username = Annotated[str, StringConstraints(min_length=1, max_length=128)]
# 暗号化後に VARCHAR(256) に収まる長さに制限
Secret = Annotated[str, StringConstraints(max_length=100)]
Port = Annotated[int, Field(ge=1, le=65535)]
PrivateKey = Annotated[str, StringConstraints(max_length=MAX_PRIVATE_KEY_LENGTH)]
# 応答待ち時間（秒）。収集ロックの保持時間（15分）に収まる範囲
ReadTimeoutSec = Annotated[int, Field(ge=10, le=600)]


class DeviceCreate(BaseModel):
    name: Name
    hostname: Host
    platform: Platform
    port: Port = 22
    # 認証情報プロファイルを使うときは、username・password・private_key・key_passphrase・enable_secret は使わない
    credential_profile_id: str | None = None
    username: Username | None = None
    # 認証はパスワード・SSH秘密鍵のどちらか、または両方
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    enable_secret: Secret | None = None
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool = True
    jump_host_id: str | None = None  # 経由する踏み台（未指定なら直接接続）
    group_id: str | None = None  # 所属グループ（未指定なら未分類）
    read_timeout: ReadTimeoutSec | None = None  # 応答待ち時間（未指定なら既定値）

    @model_validator(mode="after")
    def _need_auth(self):
        if self.credential_profile_id:
            return self  # 認証情報はプロファイルのものを使う
        if not self.username:
            raise ValueError("ユーザー名を入力してください（認証情報プロファイルを使う場合は不要です）")
        if not self.password and not self.private_key:
            raise ValueError("パスワードとSSH秘密鍵の少なくとも一方を指定してください")
        return self


class DeviceUpdate(BaseModel):
    """部分更新。password / private_key / key_passphrase / enable_secret は空文字または未指定なら変更しない。
    削除したい場合は clear_password / clear_private_key / clear_enable_secret を指定する。
    credential_profile_id を指定すると機器側の認証情報は消し、null を明示してプロファイルを外すときは
    username と password / private_key の入力が必要"""

    name: Name | None = None
    hostname: Host | None = None
    platform: Platform | None = None
    port: Port | None = None
    username: Username | None = None
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    enable_secret: Secret | None = None
    clear_password: bool = False
    clear_private_key: bool = False
    clear_enable_secret: bool = False
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool | None = None
    jump_host_id: str | None = None  # null を明示すると直接接続に戻す
    group_id: str | None = None  # null を明示すると未分類に戻す
    credential_profile_id: str | None = None  # null を明示するとこの機器だけの認証情報に戻す
    read_timeout: ReadTimeoutSec | None = None  # null を明示すると既定値に戻す


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    hostname: str
    platform: str
    port: int
    username: str | None  # 接続に使うユーザー名（プロファイルを使う機器はプロファイルのもの）
    description: str | None
    is_active: bool
    # 以下の has_* と key_info は、接続に実際に使う認証情報（プロファイルを使う機器はプロファイルのもの）を表す
    has_enable_secret: bool = False
    has_password: bool = False
    has_private_key: bool = False
    key_info: str | None = None  # 例: "ssh-ed25519 SHA256:..."（秘密鍵そのものは返さない）
    jump_host_id: str | None = None
    jump_host_name: str | None = None
    credential_profile_id: str | None = None
    credential_profile_name: str | None = None
    read_timeout: int | None = None
    group_id: str | None = None
    group_name: str | None = None
    # 機器台帳（収集のときに自動で読み取る。未取得・対象外の機種は null）
    model: str | None = None
    serial_number: str | None = None
    os_version: str | None = None
    reported_hostname: str | None = None
    inventory_at: datetime | None = None


@dataclass
class _Refs:
    """一覧の組み立てに使う参照先（機器ごとに DB を引かないよう、まとめて読んでおく）"""

    names: dict[str, str]  # 踏み台・グループ・プロファイルの id → 名前（どれも UUID なので1つの辞書にまとめる）
    profiles: dict[str, CredentialProfile]
    key_infos: dict[str, str | None] = field(default_factory=dict)  # プロファイルごとの鍵の表示（同じ鍵を何度も読まない）


async def _refs(db: AsyncSession) -> _Refs:
    names = dict((await db.execute(select(JumpHost.id, JumpHost.name))).all())
    names.update(dict((await db.execute(select(DeviceGroup.id, DeviceGroup.name))).all()))
    profiles = {p.id: p for p in (await db.execute(select(CredentialProfile))).scalars().all()}
    names.update({pid: p.name for pid, p in profiles.items()})
    return _Refs(names, profiles)


def _to_response(device: Device, refs: _Refs) -> DeviceResponse:
    resp = DeviceResponse.model_validate(device)
    profile = refs.profiles.get(device.credential_profile_id) if device.credential_profile_id else None
    cred = effective_credentials(device, profile)  # 接続と同じ関数で決める（表示と実際の接続を食い違わせない）
    resp.username = cred.username
    resp.has_enable_secret = bool(cred.enable_secret)
    resp.has_password = bool(cred.password)
    resp.has_private_key = bool(cred.private_key)
    if profile is not None:
        if profile.id not in refs.key_infos:
            refs.key_infos[profile.id] = key_info(profile)
        resp.key_info = refs.key_infos[profile.id]
    else:
        resp.key_info = key_info(cred)
    resp.jump_host_name = refs.names.get(device.jump_host_id) if device.jump_host_id else None
    resp.group_name = refs.names.get(device.group_id) if device.group_id else None
    resp.credential_profile_name = profile.name if profile is not None else None
    return resp


def _validated_key(private_key: str, passphrase: str | None) -> str:
    try:
        load_private_key(private_key, passphrase)
    except PrivateKeyError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return normalize_private_key(private_key)


async def _check_jump_host(db: AsyncSession, jump_host_id: str | None) -> None:
    if jump_host_id and not await db.get(JumpHost, jump_host_id):
        raise HTTPException(status_code=422, detail="指定された踏み台サーバが存在しません")


async def _check_profile(db: AsyncSession, profile_id: str) -> CredentialProfile:
    profile = await db.get(CredentialProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=422, detail="指定された認証情報プロファイルが存在しません")
    return profile


async def _require_profile_use(db: AsyncSession, user, profile: CredentialProfile) -> None:
    """このプロファイルを機器に割り当ててよいか（所有者・管理グループ・使用を許可されたグループ）"""
    if not (await profile_access.load(db, user)).can_use(profile):
        raise HTTPException(status_code=403, detail=profile_access.deny_use(profile.name))


def _notify_profile_owner(background: BackgroundTasks, profile: CredentialProfile, user, what: str,
                          devices: list[str]) -> None:
    """自分以外がプロファイルを機器に割り当てた・接続先を変えたときに、所有者へ知らせる"""
    if profile.owner_id and profile.owner_id != user.id:
        names = "、".join(devices[:10]) + (f" ほか {len(devices) - 10} 台" if len(devices) > 10 else "")
        background.add_task(
            notify_profile_owner, profile.owner_id, f"認証情報プロファイル「{profile.name}」{what}",
            f"{user.username} さんが、あなたが所有する認証情報プロファイル「{profile.name}」{what}。",
            [("操作した人", user.username), ("機器", names)])


async def _check_group(db: AsyncSession, group_id: str | None) -> None:
    if group_id and not await db.get(DeviceGroup, group_id):
        raise HTTPException(status_code=422, detail="指定されたグループが存在しません")


async def _get_or_404(db: AsyncSession, device_id: str) -> Device:
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


async def _commit_or_409(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前のデバイスが既に登録されています") from e


@router.get("/", response_model=list[DeviceResponse], dependencies=[Depends(require(Perm.DEVICE_READ))])
async def list_devices(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).order_by(Device.name))
    refs = await _refs(db)
    return [_to_response(d, refs) for d in result.scalars().all()]


@router.get("/export", dependencies=[Depends(require(Perm.DEVICE_READ))])
async def export_devices(db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """機器台帳を CSV で出力する（認証情報は含めない。認証情報プロファイルは名前だけ出す）"""
    devices = (await db.execute(select(Device).order_by(Device.name))).scalars().all()
    names = (await _refs(db)).names
    audit("device.export", detail={"rows": len(devices)})
    await db.commit()
    header = ["名前", "ホスト / IP", "ポート", "グループ", "機種", "モデル", "シリアル番号", "OS バージョン",
              "機器側のホスト名", f"機器情報の取得日時（{settings.TIMEZONE}）", "踏み台", "認証情報プロファイル",
              "有効", "説明"]
    rows = [[d.name, d.hostname, d.port, names.get(d.group_id), PLATFORMS[d.platform].label if d.platform in PLATFORMS
             else d.platform, d.model, d.serial_number, d.os_version, d.reported_hostname, d.inventory_at,
             names.get(d.jump_host_id), names.get(d.credential_profile_id), d.is_active, d.description]
            for d in devices]
    return csv_response(header, rows, export_name("devices"))


@router.post(
    "/",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Perm.DEVICE_WRITE))],
)
async def create_device(payload: DeviceCreate, background: BackgroundTasks, db: AsyncSession = Depends(get_db),
                        audit: Audit = Depends(get_audit)):
    data = payload.model_dump()
    data["credential_profile_id"] = data.get("credential_profile_id") or None
    profile = None
    if data["credential_profile_id"]:
        # プロファイルを使う機器は、機器側の認証情報を保存しない（送られてきても捨てる）
        profile = await _check_profile(db, data["credential_profile_id"])
        await _require_profile_use(db, audit.user, profile)
        for f in CREDENTIAL_FIELDS:
            data[f] = None
    else:
        for f in ("password", "enable_secret", "key_passphrase"):
            data[f] = data.get(f) or None
        if data.get("private_key"):
            data["private_key"] = _validated_key(data["private_key"], data["key_passphrase"])
        else:
            data["private_key"] = data["key_passphrase"] = None
    data["jump_host_id"] = data.get("jump_host_id") or None
    await _check_jump_host(db, data["jump_host_id"])
    data["group_id"] = data.get("group_id") or None
    await _check_group(db, data["group_id"])
    device = Device(id=str(uuid.uuid4()), **data)
    db.add(device)
    audit("device.create", target_type="device", target_id=device.id, target_name=device.name,
          detail={"hostname": device.hostname, "platform": device.platform, "port": device.port,
                  "username": device.username, "jump_host_id": device.jump_host_id, "group_id": device.group_id,
                  **({"credential_profile": profile.name, "auth": ["credential_profile"]} if profile else
                     {"auth": [k for k in ("password", "private_key") if data.get(k)]})})
    await _commit_or_409(db)
    await db.refresh(device)
    if profile is not None:
        _notify_profile_owner(background, profile, audit.user, "が機器に割り当てられました", [device.name])
    return _to_response(device, await _refs(db))


class DeviceDefaults(BaseModel):
    read_timeout: int


class PlatformInfo(BaseModel):
    id: str
    label: str
    vendor: str
    icon: str
    supports_enable: bool
    note: str | None = None
    inventory: bool = False  # 機器台帳（モデル・シリアル番号など）の自動取得に対応しているか


# 注意: "/defaults" "/platforms" "/collect/all" "/import" は "/{device_id}" 系より先に定義する
@router.get("/import/template", dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def import_template():
    """CSV 一括登録のひな形（見出しは台帳 CSV とそろえ、認証情報の列を足したもの）"""
    header, rows = device_import.template_rows()
    return csv_response(header, rows, "device_import_template.csv")


@router.post("/import", dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def import_devices(
    background: BackgroundTasks,
    file: UploadFile = File(...),
    dry_run: bool = Form(True),  # 既定は確認だけ（うっかり登録しないように）
    skip_errors: bool = Form(False),  # True: エラーの行を飛ばして正しい行だけ登録する
    on_duplicate: Literal["skip", "error"] = Form("skip"),  # 既にある機器と名前が同じ行の扱い
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """CSV から機器をまとめて登録する。dry_run=true は確認だけで DB を変えない

    本登録でも必ず検証し直す（確認から登録までの間に機器が増えることがあるため）。
    結果・エラー・監査ログにはパスワードなどの認証情報を入れない
    """
    raw = await file.read(device_import.MAX_IMPORT_BYTES + 1)
    if len(raw) > device_import.MAX_IMPORT_BYTES:
        raise HTTPException(status_code=422, detail="ファイルが大きすぎます（1MB まで）。ファイルを分けてください")
    try:
        text, encoding = device_import.decode(raw)
        parsed = device_import.parse(text)
    except device_import.ImportFormatError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    del raw, text
    access = await profile_access.load(db, audit.user)
    all_profiles = (await db.execute(select(CredentialProfile))).scalars().all()
    usable = {p.id for p in all_profiles if access.can_use(p)}
    results = await device_import.validate(db, parsed, on_duplicate, usable)
    counts = {s: sum(r.status == s for r in results) for s in ("ok", "error", "skip")}
    created: list[Device] = []
    if not dry_run and counts["ok"] and (skip_errors or not counts["error"]):
        for r in results:
            if r.status != "ok" or r.data is None:
                continue
            data = {**r.data, "private_key": None, "key_passphrase": None}
            data["enable_secret"] = data.get("enable_secret") or None
            if data.get("credential_profile_id"):
                for f in CREDENTIAL_FIELDS:
                    data[f] = None  # プロファイルを使う行は、機器側の認証情報を保存しない
            device = Device(id=str(uuid.uuid4()), **data)
            db.add(device)
            created.append(device)
            auth = ({"credential_profile": r.credential_profile, "auth": ["credential_profile"]}
                    if device.credential_profile_id else {"auth": ["password"]})
            audit("device.create", target_type="device", target_id=device.id, target_name=device.name,
                  detail={"hostname": device.hostname, "platform": device.platform, "port": device.port,
                          "username": device.username, "jump_host_id": device.jump_host_id,
                          "group_id": device.group_id, **auth, "via": "csv"})
        audit("device.import", detail={"rows": len(results), "created": len(created), "skipped": counts["skip"],
                                       "errors": counts["error"], "skip_errors": skip_errors,
                                       "on_duplicate": on_duplicate, "encoding": encoding,
                                       "names": [d.name for d in created[:30]]})
        try:
            await db.commit()
        except IntegrityError as e:
            await db.rollback()
            raise HTTPException(status_code=409, detail="ほかの操作で同じ名前の機器が登録されました。"
                                                        "もう一度「内容を確認」からやり直してください") from e
        for p in all_profiles:  # ほかの人のプロファイルを割り当てたら、所有者へ知らせる
            names = [d.name for d in created if d.credential_profile_id == p.id]
            if names:
                _notify_profile_owner(background, p, audit.user, "が機器に割り当てられました（CSV 取り込み）", names)
    return {
        "dry_run": dry_run, "encoding": encoding, "total": len(results), **counts,
        "created": len(created), "registered": bool(created), "ignored_columns": parsed.ignored_columns,
        "rows": [r.public() for r in results],
    }

@router.get("/defaults", response_model=DeviceDefaults, dependencies=[Depends(require(Perm.DEVICE_READ))])
async def device_defaults():
    """画面表示用の既定値（応答待ち時間など）"""
    return DeviceDefaults(read_timeout=settings.SSH_READ_TIMEOUT)


@router.get("/collect-status", dependencies=[Depends(require(Perm.DEVICE_READ))])
async def collect_status(db: AsyncSession = Depends(get_db)):
    """機器ごとの収集の状態。デバイス管理の画面が数秒おきに読む

    active: いま動いている機器だけ（queued=待ち / running=収集中 / retry=再試行待ち）
    last  : 最後の収集の結果（一度も収集していない機器は含まない）
    """
    ids = (await db.execute(select(Device.id))).scalars().all()
    active: dict[str, dict] = {}
    available = True
    if ids:
        try:
            raws = await login_limit.client().mget([collect_state.key(i) for i in ids])
        except RedisError:  # Redis が使えないときは「動いているかは分からない」として、最後の結果だけ返す
            raws, available = [], False
        now = datetime.now().timestamp()
        for device_id, raw in zip(ids, raws, strict=False):
            v = collect_state.parse(raw)
            if v:
                active[device_id] = {"state": v["state"], "seconds": max(0, int(now - float(v.get("since") or now))),
                                     "triggered_by": v.get("triggered_by")}
    latest = select(CollectLog.device_id, func.max(CollectLog.started_at).label("at")).group_by(
        CollectLog.device_id).subquery()
    logs = (await db.execute(select(CollectLog).join(
        latest, (CollectLog.device_id == latest.c.device_id) & (CollectLog.started_at == latest.c.at)))).scalars().all()
    last = {log.device_id: {"status": log.status, "at": log.finished_at or log.started_at,
                            "message": (log.message or "")[:300] or None} for log in logs}
    return {"active": active, "last": last, "available": available}


@router.get("/platforms", response_model=list[PlatformInfo], dependencies=[Depends(require(Perm.DEVICE_READ))])
async def list_platforms():
    """対応プラットフォームの一覧（画面の選択肢・表示名・構成図の既定アイコンに使う）"""
    return [
        PlatformInfo(id=k, label=v.label, vendor=v.vendor, icon=v.icon, supports_enable=v.supports_enable, note=v.note,
                     inventory=inventory.supported(k))
        for k, v in PLATFORMS.items()
    ]


@router.post("/collect/all", dependencies=[Depends(require(Perm.COLLECT))])
async def trigger_collect_all(db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """全デバイスのコンフィグ収集をトリガー"""
    task = collect_all_devices.delay("manual", audit.user.username)
    # task_id で、アクティビティログの収集結果（各機器）とつながる
    audit("collect.run", target_type="device", target_name="全機器", detail={"task_id": task.id})
    await db.commit()
    return {"task_id": task.id, "status": "queued"}


@router.get("/{device_id}", response_model=DeviceResponse, dependencies=[Depends(require(Perm.DEVICE_READ))])
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)):
    return _to_response(await _get_or_404(db, device_id), await _refs(db))


@router.put("/{device_id}", response_model=DeviceResponse, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_device(
    device_id: str, payload: DeviceUpdate, background: BackgroundTasks, db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    device = await _get_or_404(db, device_id)
    data = payload.model_dump(exclude_unset=True)
    profile = None
    if "credential_profile_id" in data:
        data["credential_profile_id"] = data["credential_profile_id"] or None
        if data["credential_profile_id"]:
            profile = await _check_profile(db, data["credential_profile_id"])
    use_profile = data.get("credential_profile_id", device.credential_profile_id)
    leaving_profile = bool(device.credential_profile_id) and not use_profile
    assigning = bool(profile) and profile.id != device.credential_profile_id
    if assigning:
        await _require_profile_use(db, audit.user, profile)
    # プロファイルを使い続ける機器の接続先（ホスト・ポート・踏み台）を変えるのも「使用」に当たる。
    # 接続先を書き換えると、次の接続でプロファイルのパスワードがそこへ送られるため
    retarget = [k for k in ("hostname", "port") if data.get(k) is not None and data[k] != getattr(device, k)]
    if "jump_host_id" in data and (data["jump_host_id"] or None) != device.jump_host_id:
        retarget.append("jump_host_id")  # 踏み台の付け替え・取り外し
    kept_profile = None
    if retarget and use_profile and use_profile == device.credential_profile_id:
        kept_profile = await _check_profile(db, use_profile)
        await _require_profile_use(db, audit.user, kept_profile)
    if use_profile:
        # プロファイルを使う機器では、機器側の認証情報の入力は使わない（保存もしない）
        for f in (*CREDENTIAL_FIELDS, "clear_password", "clear_private_key", "clear_enable_secret"):
            data.pop(f, None)
    detail = changed_fields(data, {"password", "private_key", "key_passphrase", "enable_secret"})
    if "credential_profile_id" in data:
        detail["credential_profile"] = profile.name if profile else None  # 付け替えを名前でも残す
    audit("device.update", target_type="device", target_id=device.id, target_name=device.name, detail=detail)
    clear_enable = data.pop("clear_enable_secret", False)
    clear_password = data.pop("clear_password", False)
    clear_key = data.pop("clear_private_key", False)
    new_key = data.pop("private_key", None)
    new_passphrase = data.pop("key_passphrase", None)
    for secret_field in ("password", "enable_secret"):
        if not data.get(secret_field):
            data.pop(secret_field, None)
    if "jump_host_id" in data:
        data["jump_host_id"] = data["jump_host_id"] or None
        await _check_jump_host(db, data["jump_host_id"])
    if "group_id" in data:
        data["group_id"] = data["group_id"] or None
        await _check_group(db, data["group_id"])
    for k, v in data.items():
        if v is None and k in ("name", "hostname", "platform", "port", "username", "is_active"):
            continue  # 必須項目に null は入れない
        setattr(device, k, v)
    if clear_enable:
        device.enable_secret = None
    if clear_password:
        device.password = None
    if clear_key:
        device.private_key = None
        device.key_passphrase = None
    elif new_key:
        device.private_key = _validated_key(new_key, new_passphrase or None)
        device.key_passphrase = new_passphrase or None
    elif new_passphrase and device.private_key:
        _validated_key(device.private_key, new_passphrase)  # 鍵はそのままでパスフレーズだけ変更
        device.key_passphrase = new_passphrase
    if use_profile:
        # 古い秘密の値を残さない（プロファイルを外した後に、知らないうちに古い値で接続しないように）
        for f in CREDENTIAL_FIELDS:
            setattr(device, f, None)
    elif leaving_profile and (not device.username or not (device.password or device.private_key)):
        raise HTTPException(status_code=422, detail="認証情報プロファイルを外すときは、この機器のユーザー名と、"
                                                    "パスワードまたはSSH秘密鍵を入力してください")
    elif not device.username:
        raise HTTPException(status_code=422, detail="ユーザー名を入力してください")
    elif not device.password and not device.private_key:
        raise HTTPException(status_code=422, detail="パスワードとSSH秘密鍵の両方を削除することはできません")
    await _commit_or_409(db)
    await db.refresh(device)
    if assigning:
        _notify_profile_owner(background, profile, audit.user, "が機器に割り当てられました", [device.name])
    elif kept_profile is not None:
        _notify_profile_owner(background, kept_profile, audit.user, "を使う機器の接続先が変更されました", [device.name])
    return _to_response(device, await _refs(db))


@router.delete(
    "/{device_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.DEVICE_WRITE))]
)
async def delete_device(device_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """デバイスを削除する（Gitの履歴ディレクトリは監査用に残す）"""
    device = await _get_or_404(db, device_id)
    await db.execute(delete(ComplianceResult).where(ComplianceResult.device_id == device.id))
    await db.execute(delete(ComplianceException).where(ComplianceException.device_id == device.id))
    await delete_device_monitoring(db, device.id)
    await db.execute(delete(ConfigComment).where(ConfigComment.device_id == device.id))
    await db.execute(delete(ConfigReview).where(ConfigReview.device_id == device.id))
    await db.delete(device)
    audit("device.delete", target_type="device", target_id=device.id, target_name=device.name,
          detail={"hostname": device.hostname})
    await db.commit()


@router.post("/{device_id}/collect", dependencies=[Depends(require(Perm.COLLECT))])
async def trigger_collect(device_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """単一デバイスのコンフィグ収集をトリガー"""
    device = await _get_or_404(db, device_id)
    await run_in_threadpool(mark_collect_queued, device_id, "manual")
    task = collect_device_config.delay(device_id, "manual", audit.user.username)
    audit("collect.run", target_type="device", target_id=device.id, target_name=device.name,
          detail={"task_id": task.id})
    await db.commit()
    return {"task_id": task.id, "status": "queued"}
