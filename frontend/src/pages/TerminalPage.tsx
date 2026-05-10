import React, { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";
import { api } from "../api/client";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const WS_BASE = API_BASE.replace(/^http/, "ws");

interface Device {
  id: string;
  name: string;
  hostname: string;
  platform: string;
}

export default function TerminalPage() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const navigate = useNavigate();
  const termRef = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedId, setSelectedId] = useState<string>(deviceId || "");
  const [connected, setConnected] = useState(false);
  const [status, setStatus] = useState<"idle" | "connecting" | "connected" | "error">("idle");

  useEffect(() => {
    api.get("/devices/").then((r) => setDevices(r.data));
  }, []);

  useEffect(() => {
    if (!termRef.current) return;

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
    const webLinks = new WebLinksAddon();

    term.loadAddon(fit);
    term.loadAddon(webLinks);
    term.open(termRef.current);
    fit.fit();

    term.writeln("\x1b[32mNetConfig Manager — SSH Terminal\x1b[0m");
    term.writeln("\x1b[90mデバイスを選択して接続してください\x1b[0m\r\n");

    terminal.current = term;
    fitAddon.current = fit;

    const resizeObserver = new ResizeObserver(() => fit.fit());
    resizeObserver.observe(termRef.current);

    return () => {
      resizeObserver.disconnect();
      term.dispose();
      wsRef.current?.close();
    };
  }, []);

  const connect = () => {
    if (!selectedId || !terminal.current) return;
    wsRef.current?.close();

    setStatus("connecting");
    terminal.current.writeln(`\r\n\x1b[33m接続中...\x1b[0m`);

    const ws = new WebSocket(`${WS_BASE}/api/terminal/ws/${selectedId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      setStatus("connected");
      const device = devices.find((d) => d.id === selectedId);
      terminal.current?.writeln(`\r\n\x1b[32m✓ ${device?.name} に接続しました\x1b[0m\r\n`);
    };

    ws.onmessage = (e) => {
      terminal.current?.write(e.data);
    };

    ws.onclose = () => {
      setConnected(false);
      setStatus("idle");
      terminal.current?.writeln("\r\n\x1b[31m接続が切断されました\x1b[0m\r\n");
    };

    ws.onerror = () => {
      setStatus("error");
      terminal.current?.writeln("\r\n\x1b[31mSSH接続エラー\x1b[0m\r\n");
    };

    // キー入力をWebSocketへ転送
    terminal.current.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(data);
    });

    // リサイズをサーバーへ通知
    terminal.current.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols, rows }));
      }
    });
  };

  const disconnect = () => {
    wsRef.current?.close();
    setConnected(false);
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
            <span style={{ fontSize: 12, color: "var(--color-muted)" }}>
              {selectedDevice.hostname}
            </span>
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
