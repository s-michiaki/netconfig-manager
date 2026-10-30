"""Ping監視: サーバーから ICMP Echo を送って応答時間を測る（icmplib）

ICMP の送信には次のどちらかが必要（docker-compose で両方を設定している）
- 特権ソケット: root ＋ CAP_NET_RAW
- 非特権ソケット: カーネル設定 net.ipv4.ping_group_range にプロセスのグループが含まれること
最初の送信でどちらが使えるかを確かめ、以後はそれを使う。
"""
import asyncio
import ipaddress
import logging
import re
import time

import icmplib

from app.core.config import settings

logger = logging.getLogger(__name__)

MAX_CONCURRENCY = 200  # 同時に送る PING の数（大量の対象でもソケットを使い切らないように）

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


class PingUnavailable(Exception):
    """この環境では ICMP を送れない"""


def valid_address(value: str) -> bool:
    """IP アドレス（v4 / v6）またはホスト名か"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(value))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_privileged: bool | None = None  # None: 未判定


async def _ping_once(address: str, timeout: float, privileged: bool) -> float | None:
    host = await icmplib.async_ping(address, count=1, timeout=timeout, privileged=privileged)
    return round(host.avg_rtt, 2) if host.is_alive else None


async def ping_one(address: str, timeout: float) -> float | None:
    """1回 PING して応答時間（ミリ秒）を返す。応答が無ければ None"""
    global _privileged
    if _privileged is None:
        for priv in (True, False):
            try:
                rtt = await _ping_once(address, timeout, priv)
            except (icmplib.SocketPermissionError, PermissionError):
                continue
            _privileged = priv
            logger.info("Ping監視: %s ソケットで ICMP を送信します", "特権" if priv else "非特権")
            return rtt
        raise PingUnavailable(
            "サーバーから PING を送れません。backend コンテナに NET_RAW 権限、"
            "または net.ipv4.ping_group_range の設定が必要です"
        )
    return await _ping_once(address, timeout, _privileged)


async def resolve(address: str) -> str:
    """ホスト名を IP アドレスに変換する（IP ならそのまま）。失敗したら ValueError"""
    if _is_ip(address):
        return address
    try:
        ips = await icmplib.async_resolve(address)
    except icmplib.NameLookupError as e:
        raise ValueError("名前解決できません") from e
    if not ips:
        raise ValueError("名前解決できません")
    return ips[0]


async def ping_many(addresses: dict[str, str], timeout: float | None = None) -> dict[str, float | None]:
    """{キー: IP} にまとめて PING する。戻り値は {キー: 応答時間(ms) または None}"""
    timeout = timeout or settings.PING_TIMEOUT
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def one(key: str, ip: str) -> tuple[str, float | None]:
        async with sem:
            try:
                return key, await ping_one(ip, timeout)
            except PingUnavailable:
                raise
            except Exception as e:  # noqa: BLE001 - 送信できない宛先（ルートなし等）は応答なし扱い
                logger.debug("PING 失敗 %s: %r", ip, e)
                return key, None

    pairs = await asyncio.gather(*(one(k, ip) for k, ip in addresses.items()))
    return dict(pairs)


class Ticker:
    """一定間隔で処理を呼ぶ。処理が間隔より長くかかったら、遅れを取り戻そうとせず次の周期から再開する"""

    def __init__(self, interval: float):
        self.interval = interval
        self.next = time.monotonic()

    async def wait(self) -> None:
        self.next += self.interval
        delay = self.next - time.monotonic()
        if delay < 0:
            self.next = time.monotonic()
            delay = 0
        await asyncio.sleep(delay)
