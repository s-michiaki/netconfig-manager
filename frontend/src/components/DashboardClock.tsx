import { memo, useEffect, useState } from "react";

/**
 * ダッシュボードの見出しに出す現在の日時（例: 2026/11/26（木）11:38）。
 * - 表示するタイムゾーンは画面のほかの日時と同じ、ブラウザのタイムゾーン
 * - ブラウザの時計だけで動かす（サーバーには問い合わせない）
 * - 秒は出さない。毎回 new Date() から表示を作り、次の「分」の境目に合わせて更新する（分が変わった直後に切り替わる）
 * - タブが裏にあるあいだは止め、戻ったらすぐ正しい時刻にする
 * - 親（ダッシュボード）を描き直さないよう、この部品の中だけで状態を持つ
 */

const WEEKDAYS = ["日", "月", "火", "水", "木", "金", "土"];
const pad = (n: number) => String(n).padStart(2, "0");

/** 表示用の文字列。`YYYY/MM/DD（曜）HH:MM`（24 時間表記）。曜日は日本語の固定表記。1 回の整形で 3 つとも返す */
export function formatClock(d: Date): { date: string; time: string; iso: string } {
  const ymd = `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())}`;
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return {
    date: `${ymd}（${WEEKDAYS[d.getDay()]}）`,
    time,
    iso: `${ymd.replace(/\//g, "-")}T${time}`,
  };
}

function DashboardClock() {
  const [clock, setClock] = useState(() => formatClock(new Date()));

  useEffect(() => {
    let timer: number | undefined;
    const stop = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = undefined;
    };
    const tick = () => {
      stop();
      const d = new Date();
      const next = formatClock(d);
      // 同じ分のままなら state を変えない（再描画しない）
      setClock((prev) => (prev.iso === next.iso ? prev : next));
      // 次の分の境目の直後。ただしスリープ復帰などの取りこぼしに備え、最長 10 秒で見直す
      const toNextMinute = 60_000 - (d.getSeconds() * 1000 + d.getMilliseconds()) + 50;
      timer = window.setTimeout(tick, Math.min(toNextMinute, 10_000));
    };
    // 表に戻った・スリープから復帰した（focus / pageshow）ときは、いますぐ直して予約し直す
    const refresh = () => {
      if (document.visibilityState === "visible") tick();
      else stop();
    };
    refresh();
    document.addEventListener("visibilitychange", refresh);
    window.addEventListener("focus", refresh);
    window.addEventListener("pageshow", refresh);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", refresh);
      window.removeEventListener("focus", refresh);
      window.removeEventListener("pageshow", refresh);
    };
  }, []);

  return (
    <time className="dash-clock topo-muted topo-small" dateTime={clock.iso} data-testid="dash-clock">
      <span className="dash-clock-date">{clock.date}</span>
      {clock.time}
    </time>
  );
}

export default memo(DashboardClock);
