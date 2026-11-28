import { useCallback, useEffect, useRef, useState } from "react";
import { api, IDLE_REASON, IDLE_SENT_KEY, isIdleLogout, redirectToLogin, setLogoutReason } from "./api/client";

/**
 * 無操作によるログアウト（backend の services/idle.py と対になる画面側）
 *
 * - 判定はサーバー側（最後の操作から IDLE_TIMEOUT_MIN 分を過ぎたログインは 401）。画面側は、切れる 1 分前の予告と、
 *   時間が来たときにログイン画面へ移す役
 * - 「操作」は、マウス・キーボード・タッチの操作（pointerdown・keydown・wheel・touchstart）。画面の自動の更新は数えない。
 *   ターミナル（xterm.js）はキー入力のイベントを止めるので、捕捉（capture）の段階で受ける
 * - サーバーへの合図（POST /api/auth/activity）は間引いて送る（最後に送ってから 60 秒、短い設定ならその 1/4 たってから）
 * - 時刻は localStorage でほかのタブと共有する（storage イベントで受ける）
 *     ncm.idle.sent   : サーバーが最後の操作として数えた時刻（合図を送った時刻。ログインの完了もここ）。期限の基準
 *     ncm.idle.last   : 最後に操作した時刻（まだ送っていない操作があるかを見る）
 *     ncm.idle.ping   : Ping 監視が動いているタブが、10 秒ごとに書く時刻（監視中は予告を出さない）
 *     ncm.idle.logout : 無操作でログアウトした時刻（ほかのタブも同時にログイン画面へ）
 * - 時間が来たら POST /api/auth/logout に {"reason": "idle"} を付けて送る（サーバーは、このログインだけを無操作として失効させる。
 *   Redis に届かなくても、ふつうのログアウトと違って、ほかの端末までは切らない）。手元のトークンは必ず捨てる
 * - 画面側は、サーバーの期限より少し早く（MARGIN_MS）動く。「続ける」を押した直後に切られないように。
 *   判定はタイマーの回数ではなく時刻の差で行う（PC のスリープから戻ったら、すぐにログイン画面へ）
 */

const SENT_KEY = IDLE_SENT_KEY;
const LAST_KEY = "ncm.idle.last";
const PING_KEY = "ncm.idle.ping";
const LOGOUT_KEY = "ncm.idle.logout";

const WARN_MS = 60_000; // 予告を出す時間（切れる 1 分前）
const MARGIN_MS = 10_000; // サーバーの期限より早く動く分
const CHECK_MS = 1_000;
const RETRY_MS = 5_000; // 予告の時間に、まだ送っていない操作を送り直す間隔
const PING_BEAT_MS = 10_000; // Ping 監視中の印を書く間隔
const PING_FRESH_MS = 30_000; // この時間内に印があれば「監視中」（タブが閉じた・落ちたら、印は自然に古くなる）
// 監視を止めたあと、サーバーが最後に時刻を進めたのは印より前かもしれない（サーバーは 20 秒ごと・tick のときに進める）。
// その分を引いて、早めに数える
const PING_LAG_MS = 45_000;
const EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

function readNum(key: string): number {
  try {
    const v = Number(localStorage.getItem(key));
    return Number.isFinite(v) ? v : 0;
  } catch {
    return 0;
  }
}

function writeNum(key: string, v: number) {
  try {
    localStorage.setItem(key, String(v));
  } catch {
    /* 保存できなくても、このタブの中では動く */
  }
}

/** Ping 監視が動いている間（active）、ほかのタブにも「監視中」を伝える（PingPage.tsx） */
export function useIdlePingHold(active: boolean) {
  useEffect(() => {
    if (!active) return;
    writeNum(PING_KEY, Date.now());
    const t = window.setInterval(() => writeNum(PING_KEY, Date.now()), PING_BEAT_MS);
    return () => {
      window.clearInterval(t);
      writeNum(PING_KEY, Date.now()); // 止めた時刻（ここから PING_LAG_MS を引いて数え始める）
    };
  }, [active]);
}

/** ログイン後のレイアウト（App.tsx）に 1 か所だけ置く。minutes が 0 のときは何もしない */
export function IdleGuard({ minutes }: { minutes: number }) {
  const [warnSec, setWarnSec] = useState<number | null>(null);
  const inflight = useRef(false);
  const lastTry = useRef(0);
  const failed = useRef(false);
  const leaving = useRef(false);
  const timeoutMs = minutes * 60_000;
  const throttleMs = Math.min(60_000, timeoutMs / 4);

  const leave = useCallback(async (callServer: boolean) => {
    if (leaving.current) return;
    leaving.current = true;
    setLogoutReason(IDLE_REASON);
    setWarnSec(null);
    if (callServer) {
      writeNum(LOGOUT_KEY, Date.now());
      try {
        await api.post("/auth/logout", { reason: "idle" }, { timeout: 5000 });
      } catch {
        /* すでに切れている・届かない。画面側では捨てる */
      }
    }
    redirectToLogin(undefined, IDLE_REASON);
  }, []);

  /** サーバーに操作の合図を送る。成功したら、送った時刻を期限の基準にする */
  const send = useCallback(async () => {
    if (inflight.current || leaving.current) return;
    inflight.current = true;
    lastTry.current = Date.now();
    const at = Date.now();
    try {
      await api.post("/auth/activity", null, { timeout: 10_000 });
      writeNum(SENT_KEY, Math.max(readNum(SENT_KEY), at));
      failed.current = false;
    } catch (err) {
      // 401（無操作・失効）は client.ts がログイン画面へ移す。届かないときは予告を出して待つ
      if (!isIdleLogout(err)) failed.current = true;
    } finally {
      inflight.current = false;
    }
  }, []);

  const check = useCallback(() => {
    if (leaving.current) return;
    const now = Date.now();
    const ping = readNum(PING_KEY);
    if (ping && now - ping < PING_FRESH_MS) {
      setWarnSec(null); // Ping 監視中（このタブか、ほかのタブ）。サーバーも時刻を進めている
      return;
    }
    const ref = Math.max(readNum(SENT_KEY), ping ? ping - PING_LAG_MS : 0);
    if (readNum(LOGOUT_KEY) > ref) {
      void leave(false); // ほかのタブが、いまの基準のあとに無操作でログアウトした（サーバーへ重ねて送らない）
      return;
    }
    const expireAt = ref + timeoutMs - MARGIN_MS;
    if (now >= expireAt) {
      void leave(true);
      return;
    }
    if (now < expireAt - WARN_MS) {
      setWarnSec(null);
      return;
    }
    // 予告の時間。まだ送っていない操作（間引いた分）があれば、予告を出さずに送る
    const unsent = readNum(LAST_KEY) > ref;
    if (unsent && !failed.current) {
      if (now - lastTry.current >= RETRY_MS) void send();
      return;
    }
    if (unsent && now - lastTry.current >= RETRY_MS) void send();
    setWarnSec(Math.max(0, Math.ceil((expireAt - now) / 1000)));
  }, [timeoutMs, leave, send]);

  useEffect(() => {
    if (minutes <= 0) return;
    if (!readNum(SENT_KEY)) writeNum(SENT_KEY, Date.now()); // 基準が無い（この機能の前からのログイン）: ここから数える

    const onActivity = (e: Event) => {
      // 予告の中の操作は数えない（「続ける」「ログアウト」で決める）
      if (e.target instanceof Element && e.target.closest("[data-idle-ignore]")) return;
      const now = Date.now();
      writeNum(LAST_KEY, now);
      if (now - readNum(SENT_KEY) >= throttleMs) void send();
    };
    const onStorage = (e: StorageEvent) => {
      if (e.key === LOGOUT_KEY && e.newValue) {
        void leave(false); // ほかのタブが無操作でログアウトした
        return;
      }
      if (e.key === SENT_KEY || e.key === PING_KEY || e.key === LAST_KEY) check();
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") check();
    };
    EVENTS.forEach((ev) => window.addEventListener(ev, onActivity, { capture: true, passive: true }));
    window.addEventListener("storage", onStorage);
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", check);
    const t = window.setInterval(check, CHECK_MS);
    check();
    return () => {
      EVENTS.forEach((ev) => window.removeEventListener(ev, onActivity, { capture: true }));
      window.removeEventListener("storage", onStorage);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", check);
      window.clearInterval(t);
    };
  }, [minutes, throttleMs, send, check, leave]);

  if (minutes <= 0 || warnSec === null) return null;

  const keepGoing = async () => {
    writeNum(LAST_KEY, Date.now());
    failed.current = false;
    lastTry.current = 0;
    await send();
    check();
  };
  const logoutNow = async () => {
    leaving.current = true;
    try {
      await api.post("/auth/logout", null, { timeout: 5000 });
    } catch {
      /* 画面側では捨てる */
    }
    redirectToLogin();
  };

  // 読み上げ（aria-live）は、開いたときと、残り 30 秒・10 秒を切ったときだけ（毎秒は読ませない）
  const spoken = warnSec > 30 ? "まもなくログアウトします。続けるときは「続ける」を押してください。"
    : warnSec > 10 ? "あと 30 秒ほどでログアウトします。" : "あと 10 秒ほどでログアウトします。";

  return (
    <div className="modal-overlay" data-idle-ignore style={{ zIndex: 1000 }}
         onKeyDown={(e) => { if (e.key === "Escape") { e.preventDefault(); void keepGoing(); } }}>
      <div className="modal" role="alertdialog" aria-labelledby="idle-warn-title" aria-describedby="idle-warn-body">
        <p className="modal-title" id="idle-warn-title">まもなくログアウトします</p>
        <p id="idle-warn-body" style={{ margin: 0 }}>
          操作が無い時間が続いているため、あと <strong data-testid="idle-remaining">{warnSec}</strong> 秒でログアウトします。
          続けて使うときは「続ける」（または Esc キー）を押してください。
        </p>
        <span aria-live="polite" style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)" }}>
          {spoken}
        </span>
        <div className="btn-row">
          <button className="btn" onClick={logoutNow}>ログアウト</button>
          <button className="btn btn-primary" onClick={keepGoing} autoFocus>続ける</button>
        </div>
      </div>
    </div>
  );
}
