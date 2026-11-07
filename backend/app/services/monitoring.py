"""モニタリング（試験導入）: SNMP でのインタフェースの帯域の取得と、FW ルールのヒット数の保存

帯域: IF-MIB の 64bit カウンタ（ifHCInOctets / ifHCOutOctets）を MONITOR_INTERVAL_SEC ごとに読み、
前回の値との差から bps を計算して if_samples に記録する（使用率 = bps / ifHighSpeed）。
カウンタが戻った（機器の再起動・カウンタのクリア）ときはその回の記録を飛ばす。
SNMP は UDP でサーバーから機器へ直接届く必要がある（踏み台経由の機器は取得できない）
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.device import Device
from app.models.monitoring import FwHitStatus, FwRuleHit, IfSample, MonInterface, SnmpSetting
from app.services.fw_hits import FwHitResult

logger = logging.getLogger(__name__)

AUTH_PROTOCOLS = {"SHA": usmHMACSHAAuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol, "MD5": usmHMACMD5AuthProtocol}
PRIV_PROTOCOLS = {"AES": usmAesCfb128Protocol, "AES256": usmAesCfb256Protocol, "DES": usmDESPrivProtocol}

# IF-MIB
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
OID_HIGHSPEED = "1.3.6.1.2.1.31.1.1.1.15"
OID_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_OPER = "1.3.6.1.2.1.2.2.1.8"
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
MAX_CONCURRENT = 20  # 同時に問い合わせる機器の数
# 前回の読み取りからの間隔が「取得間隔 × この割合」より短いときは bps を計算しない（「今すぐ取得」の直後など）。
# 固定の秒数にすると、取得間隔と同じ値のとき読み取り時刻の揺れ（数百ミリ秒〜数秒）で約半分が記録されなくなる
MIN_SAMPLE_RATIO = 0.5


class SnmpError(Exception):
    pass


@dataclass
class SnmpTarget:
    device_id: str
    name: str
    host: str
    port: int
    version: str
    community: str | None = None
    v3_user: str | None = None
    v3_auth_proto: str | None = None
    v3_auth_key: str | None = None
    v3_priv_proto: str | None = None
    v3_priv_key: str | None = None


@dataclass
class IfReading:
    if_index: int
    name: str
    alias: str | None
    speed_mbps: int | None
    oper_up: bool
    in_octets: int | None
    out_octets: int | None


def target_of(s: SnmpSetting, d: Device) -> SnmpTarget:
    return SnmpTarget(d.id, d.name, d.hostname, s.port, s.version, s.community, s.v3_user, s.v3_auth_proto,
                      s.v3_auth_key, s.v3_priv_proto, s.v3_priv_key)


def _auth(t: SnmpTarget):
    if t.version == "3":
        return UsmUserData(
            t.v3_user or "",
            authKey=t.v3_auth_key or None, privKey=t.v3_priv_key or None,
            authProtocol=AUTH_PROTOCOLS.get(t.v3_auth_proto or "", usmNoAuthProtocol),
            privProtocol=PRIV_PROTOCOLS.get(t.v3_priv_proto or "", usmNoPrivProtocol),
        )
    return CommunityData(t.community or "", mpModel=1)  # v2c


async def _transport(t: SnmpTarget):
    return await UdpTransportTarget.create((t.host, t.port), timeout=settings.SNMP_TIMEOUT, retries=settings.SNMP_RETRIES)


async def _walk(engine: SnmpEngine, t: SnmpTarget, oid: str) -> dict[int, object]:
    """表の1列を読む → {ifIndex: 値}"""
    out: dict[int, object] = {}
    transport = await _transport(t)
    async for err, status, _idx, binds in bulk_walk_cmd(
        engine, _auth(t), transport, ContextData(), 0, 25, ObjectType(ObjectIdentity(oid)), lexicographicMode=False,
    ):
        if err:
            raise SnmpError(str(err))
        if status:
            raise SnmpError(status.prettyPrint())
        for name, val in binds:
            last = tuple(name)[-1]
            out[int(last)] = val
    return out


async def snmp_get_info(t: SnmpTarget, engine: SnmpEngine | None = None) -> dict[str, str]:
    """接続確認用（sysName / sysDescr）"""
    own = engine is None
    engine = engine or SnmpEngine()
    try:
        err, status, _idx, binds = await get_cmd(
            engine, _auth(t), await _transport(t), ContextData(),
            ObjectType(ObjectIdentity(OID_SYSNAME)), ObjectType(ObjectIdentity(OID_SYSDESCR)),
        )
        if err:
            raise SnmpError(str(err))
        if status:
            raise SnmpError(status.prettyPrint())
        vals = [v.prettyPrint() for _, v in binds]
        return {"sys_name": vals[0], "sys_descr": vals[1][:300]}
    finally:
        if own:
            engine.close_dispatcher()


async def poll_interfaces(t: SnmpTarget, engine: SnmpEngine) -> tuple[list[IfReading], datetime]:
    """（インタフェースごとの値, カウンタを読んだ時刻）。

    bps は前回との差を経過秒数で割って出すので、時刻は「カウンタを読んだとき」でなければならない。
    全機器の取得が終わってから時刻を取ると、応答しない機器のタイムアウト待ちの分だけ回ごとにずれる
    """
    names = await _walk(engine, t, OID_IFNAME)
    if not names:
        raise SnmpError("IF-MIB（ifXTable）を読めませんでした（機器の SNMP の設定・ビューを確認してください）")
    before = utcnow()
    hc_in = await _walk(engine, t, OID_HC_IN)
    hc_out = await _walk(engine, t, OID_HC_OUT)
    read_at = before + (utcnow() - before) / 2  # 入力・出力の2列を読んだ間の中央
    speed = await _walk(engine, t, OID_HIGHSPEED)
    alias = await _walk(engine, t, OID_ALIAS)
    oper = await _walk(engine, t, OID_OPER)
    out = []
    for idx, name in names.items():
        a = alias.get(idx)
        out.append(IfReading(
            if_index=idx, name=str(name)[:128], alias=(str(a)[:256] or None) if a is not None else None,
            speed_mbps=int(speed[idx]) if idx in speed else None,
            oper_up=int(oper.get(idx, 2)) == 1,
            in_octets=int(hc_in[idx]) if idx in hc_in else None,
            out_octets=int(hc_out[idx]) if idx in hc_out else None,
        ))
    return out, read_at


def _rate(prev: int | None, cur: int | None, seconds: float) -> float | None:
    if prev is None or cur is None or seconds <= 0 or cur < prev:  # カウンタが戻った（再起動・クリア）
        return None
    return (cur - prev) * 8 / seconds


async def store_readings(db: AsyncSession, device_id: str, readings: list[IfReading], read_at: datetime | None = None) -> int:
    """取得結果を保存する。記録した件数を返す。read_at: カウンタを読んだ時刻（bps の計算と記録の時刻に使う）"""
    now = read_at or utcnow()
    existing = {i.if_index: i for i in (await db.execute(
        select(MonInterface).where(MonInterface.device_id == device_id))).scalars()}
    saved = 0
    for r in readings:
        i = existing.get(r.if_index)
        if i is None:
            i = MonInterface(device_id=device_id, if_index=r.if_index, name=r.name)
            db.add(i)
            await db.flush()
        i.name, i.alias, i.speed_mbps, i.oper_up = r.name, r.alias, r.speed_mbps, r.oper_up
        in_bps = out_bps = None
        if i.last_at is not None:
            secs = (now - i.last_at).total_seconds()
            if secs < settings.MONITOR_INTERVAL_SEC * MIN_SAMPLE_RATIO:
                # 前回の取得から短すぎる（「今すぐ取得」の直後など）。誤差が大きいので値は更新せず、前回を基準に残す
                continue
            in_bps = _rate(i.last_in_octets, r.in_octets, secs)
            out_bps = _rate(i.last_out_octets, r.out_octets, secs)
        i.in_bps, i.out_bps = in_bps, out_bps
        if in_bps is not None and out_bps is not None and (r.oper_up or not settings.MONITOR_UP_ONLY):
            db.add(IfSample(interface_id=i.id, at=now, in_bps=in_bps, out_bps=out_bps))
            saved += 1
        i.last_in_octets, i.last_out_octets, i.last_at = r.in_octets, r.out_octets, now
    return saved


async def poll_all(db: AsyncSession) -> dict:
    """SNMP を有効にした全機器の帯域を取得する（worker から MONITOR_INTERVAL_SEC ごとに呼ぶ）"""
    rows = (await db.execute(
        select(SnmpSetting, Device).join(Device, Device.id == SnmpSetting.device_id)
        .where(SnmpSetting.enabled.is_(True), Device.is_active.is_(True))
    )).all()
    engine = SnmpEngine()
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def one(t: SnmpTarget):
        async with sem:
            try:
                readings, read_at = await poll_interfaces(t, engine)
                return t, (readings, read_at), None
            except Exception as e:  # noqa: BLE001 - 1台の失敗で全体を止めない
                return t, None, str(e) or type(e).__name__

    try:
        results = await asyncio.gather(*(one(target_of(s, d)) for s, d in rows))
    finally:
        engine.close_dispatcher()
    ok = failed = samples = 0
    by_id = {s.device_id: s for s, _ in rows}
    for t, got, err in results:
        s = by_id[t.device_id]
        s.last_polled_at = utcnow()
        if err is not None:
            s.last_error = err
            failed += 1
            continue
        s.last_error = None
        samples += await store_readings(db, t.device_id, *got)
        ok += 1
    purged = await purge_samples(db)
    await db.commit()
    return {"devices": len(rows), "ok": ok, "failed": failed, "samples": samples, "purged": purged}


async def purge_samples(db: AsyncSession) -> int:
    cutoff = utcnow() - timedelta(days=settings.MONITOR_RETENTION_DAYS)
    r = await db.execute(delete(IfSample).where(IfSample.at < cutoff))
    return r.rowcount or 0


# ---------------------------------------------------------------- FW ルールのヒット数


async def store_fw_result(db: AsyncSession, device_id: str, res: FwHitResult) -> None:
    """取得結果を保存する。失敗したときはルールの一覧は前回のまま残し、状態だけ更新する"""
    now = utcnow()
    st = await db.get(FwHitStatus, device_id)
    if st is None:
        st = FwHitStatus(device_id=device_id)
        db.add(st)
    st.collected_at, st.success, st.error = now, res.error is None, res.error
    if res.raw:
        st.raw_output = res.raw
    if res.error is not None and not res.rules:
        await db.commit()
        return
    old = {(r.rule_id or r.name): r for r in (await db.execute(
        select(FwRuleHit).where(FwRuleHit.device_id == device_id))).scalars()}
    await db.execute(delete(FwRuleHit).where(FwRuleHit.device_id == device_id))
    for r in res.rules:
        prev = old.get(r.rule_id or r.name)
        db.add(FwRuleHit(
            device_id=device_id, position=r.position, rule_id=r.rule_id, name=r.name[:256], hit_count=r.hit_count,
            prev_hit_count=prev.hit_count if prev else None, prev_collected_at=prev.collected_at if prev else None,
            packets=r.packets, bytes=r.bytes, first_hit_at=r.first_hit_at, last_hit_at=r.last_hit_at,
            collected_at=now,
        ))
    st.rule_count = len(res.rules)
    await db.commit()
