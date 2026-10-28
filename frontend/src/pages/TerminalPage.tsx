import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";
import { api, getToken, redirectToLogin, wsUrl } from "../api/client";

interface Device {
  id: string;
  name: string;
  hostname: string;
  platform: string;
}

type Status = "idle" | "connecting" | "connected" | "error";

export default function TerminalPage() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const termRef = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedId, setSelectedId] = useState<string>(deviceId || "");
  const [status, setStatus] = useState<Status>("idle");
  const connected = status === "connected" || status === "connecting";

  useEffect(() => {
    api.get("/devices/").then((r) => setDevices(r.data)).catch(() => undefined);
  }, []);

  useEffect(() => {
    const mount = termRef.current;
    if (!mount) return;

    // 生成を1フレーム遅らせる。React StrictMode の二重マウントで即座に dispose されると
    // xterm 内部のタイマーが破棄済みレンダラーを参照して例外になるため（xterm.js 5.5 の既知の問題）
    let cleanup: (() => void) | undefined;
    const raf = requestAnimationFrame(() => {
      cleanup = initTerminal(mount);
    });
    return () => {
      cancelAnimationFrame(raf);
      cleanup?.();
    };
  }, []);

  const initTerminal = (mount: HTMLDivElement) => {
    const term = new Terminal({
      theme: {
        background: "#0d1117",
        foreground: "#c9d1d9",
        cursor: "#58a6ff",
        selectionBackground: "#264f78",
      },
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      fontSize: 13,
      lineHeight: 1.4,
      cursorBlink: true,
      scrollback: 5000,
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(mount);
    fit.fit();

    term.writeln("\x1b[32mNetConfig Manager — SSH Terminal\x1b[0m");
    term.writeln("\x1b[90mデバイスを選択して接続してください\x1b[0m\r\n");

    terminal.current = term;
    fitAddon.current = fit;

    const send = (msg: object) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
    };

    // ハンドラは端末生成時に1回だけ登録し、送信先は常に現在の WebSocket を参照する
    // （接続のたびに登録すると、再接続するごとにハンドラが増え続ける）
    const dataSub = term.onData((data) => send({ type: "input", data }));
    const resizeSub = term.onResize(({ cols, rows }) => send({ type: "resize", cols, rows }));

    const resizeObserver = new ResizeObserver(() => fit.fit());
    resizeObserver.observe(mount);

    return () => {
      resizeObserver.disconnect();
      dataSub.dispose();
      resizeSub.dispose();
      wsRef.current?.close();
      wsRef.current = null;
      term.dispose();
      terminal.current = null;
    };
  };

  const connect = () => {
    const term = terminal.current;
    const token = getToken();
    if (!selectedId || !term) return;
    if (!token) return redirectToLogin();
    wsRef.current?.close();

    setStatus("connecting");
    term.writeln(`\r\n\x1b[33m接続中...\x1b[0m`);

    const ws = new WebSocket(wsUrl(`/terminal/ws/${selectedId}`));
    wsRef.current = ws;
    let received = false;

    ws.onopen = () => {
      fitAddon.current?.fit();
      // 最初のメッセージで認証し、現在の端末サイズも伝える（PTYを正しいサイズで開くため）
      ws.send(JSON.stringify({ type: "auth", token, cols: term.cols, rows: term.rows }));
    };

    ws.onmessage = (e) => {
      if (!received) {
        received = true;
        setStatus("connected");
      }
      term.write(e.data);
    };

    ws.onclose = (e) => {
      if (wsRef.current !== ws) return; // 新しい接続に置き換え済み
      wsRef.current = null;
      if (e.code === 4401) {
        term.writeln("\r\n\x1b[31m認証の有効期限が切れました。再ログインしてください\x1b[0m");
        setTimeout(redirectToLogin, 1500);
        return;
      }
      setStatus((s) => (s === "error" ? s : "idle"));
      term.writeln("\r\n\x1b[31m接続が切断されました\x1b[0m\r\n");
    };

    ws.onerror = () => {
      setStatus("error");
      term.writeln("\r\n\x1b[31mWebSocket接続エラー\x1b[0m\r\n");
    };
  };

  const disconnect = () => {
    wsRef.current?.close();
    setStatus("idle");
  };

  const selectedDevice = devices.find((d) => d.id === selectedId);

  const statusBadge = {
    idle: <span className="badge badge-neutral">未接続</span>,
    connecting: <span className="badge badge-warning">接続中...</span>,
    connected: <span className="badge badge-success">● 接続中</span>,
    error: <span className="badge badge-danger">エラー</span>,
  }[status];

  return (
    <div className="page">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span className="page-title">SSH ターミナル</span>
          {statusBadge}
          {selectedDevice && (
            <span style={{ fontSize: 12, color: "var(--color-muted)" }}>{selectedDevice.hostname}</span>
          )}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <select
            style={{ width: 200 }}
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            disabled={connected}
          >
            <option value="">デバイスを選択...</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
          {!connected ? (
            <button className="btn btn-primary" onClick={connect} disabled={!selectedId}>
              接続
            </button>
          ) : (
            <button className="btn btn-danger" onClick={disconnect}>
              切断
            </button>
          )}
        </div>
      </div>

      <div className="page-body" style={{ padding: "14px 20px" }}>
        <div className="terminal-container">
          <div className="terminal-titlebar">
            <div className="term-dot term-dot-red" />
            <div className="term-dot term-dot-yellow" />
            <div className="term-dot term-dot-green" />
            <span className="terminal-titlebar-label">
              {selectedDevice ? `SSH — ${selectedDevice.name}` : "NetConfig Terminal"}
            </span>
          </div>
          <div id="terminal-mount" ref={termRef} style={{ flex: 1, padding: 4 }} />
        </div>
      </div>
    </div>
  );
}
