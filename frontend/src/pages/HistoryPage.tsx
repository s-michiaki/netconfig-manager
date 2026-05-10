import React, { useEffect, useState } from "react";
import { api } from "../api/client";

interface Device { id: string; name: string; }
interface Commit { hash: string; full_hash: string; message: string; date: string; }

function parseDiff(diff: string) {
  return diff.split("\n").map((line, i) => {
    let cls = "diff-meta";
    if (line.startsWith("+") && !line.startsWith("+++")) cls = "diff-add";
    else if (line.startsWith("-") && !line.startsWith("---")) cls = "diff-del";
    return <div key={i} className={cls}>{line || " "}</div>;
  });
}

export default function HistoryPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState("");
  const [history, setHistory] = useState<Commit[]>([]);
  const [selectedA, setSelectedA] = useState("");
  const [selectedB, setSelectedB] = useState("");
  const [diff, setDiff] = useState("");
  const [content, setContent] = useState("");
  const [view, setView] = useState<"diff" | "content">("diff");

  useEffect(() => {
    api.get("/devices/").then((r) => setDevices(r.data));
  }, []);

  useEffect(() => {
    if (!selectedDevice) return;
    const device = devices.find((d) => d.id === selectedDevice);
    if (!device) return;
    api.get(`/configs/${device.name}/history`).then((r) => {
      setHistory(r.data);
      if (r.data.length >= 2) {
        setSelectedA(r.data[1].full_hash);
        setSelectedB(r.data[0].full_hash);
      }
    });
  }, [selectedDevice]);

  const showDiff = async () => {
    const device = devices.find((d) => d.id === selectedDevice);
    if (!device || !selectedA || !selectedB) return;
    const r = await api.get(`/configs/${device.name}/diff`, {
      params: { from_hash: selectedA, to_hash: selectedB },
    });
    setDiff(r.data.diff || "差分なし");
    setView("diff");
  };

  const showContent = async (hash: string) => {
    const device = devices.find((d) => d.id === selectedDevice);
    if (!device) return;
    const r = await api.get(`/configs/${device.name}/content/${hash}`);
    setContent(r.data);
    setView("content");
  };

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">世代管理 (Git)</span>
        <div style={{ display: "flex", gap: 8 }}>
          <select
            style={{ width: 200 }}
            value={selectedDevice}
            onChange={(e) => setSelectedDevice(e.target.value)}
          >
            <option value="">デバイスを選択...</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </div>
      </div>

      <div className="page-body" style={{ display: "flex", gap: 16, height: "100%", paddingBottom: 0 }}>
        {/* 左: コミット一覧 */}
        <div style={{ width: 360, flexShrink: 0, display: "flex", flexDirection: "column" }}>
          <p className="section-label">コミット履歴</p>
          {history.length === 0 ? (
            <p style={{ color: "var(--color-muted)", fontSize: 13 }}>
              {selectedDevice ? "履歴なし" : "デバイスを選択してください"}
            </p>
          ) : (
            <div style={{ overflow: "auto", flex: 1 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ハッシュ</th>
                    <th>日時</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((c) => (
                    <tr key={c.full_hash}>
                      <td>
                        <span className="mono" style={{ fontSize: 12, color: "var(--color-accent)" }}>
                          {c.hash}
                        </span>
                      </td>
                      <td style={{ fontSize: 11, color: "var(--color-muted)" }}>
                        {new Date(c.date).toLocaleString("ja-JP")}
                      </td>
                      <td>
                        <button
                          className="btn"
                          style={{ padding: "2px 8px", fontSize: 11 }}
                          onClick={() => showContent(c.full_hash)}
                        >
                          表示
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* 右: 差分・コンテンツビュー */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          {history.length >= 2 && (
            <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
              <select
                value={selectedA}
                onChange={(e) => setSelectedA(e.target.value)}
                style={{ width: 160 }}
              >
                {history.map((c) => <option key={c.full_hash} value={c.full_hash}>{c.hash}</option>)}
              </select>
              <span style={{ color: "var(--color-muted)" }}>→</span>
              <select
                value={selectedB}
                onChange={(e) => setSelectedB(e.target.value)}
                style={{ width: 160 }}
              >
                {history.map((c) => <option key={c.full_hash} value={c.full_hash}>{c.hash}</option>)}
              </select>
              <button className="btn btn-primary" onClick={showDiff}>差分を表示</button>
            </div>
          )}

          <p className="section-label">{view === "diff" ? "差分ビュー" : "コンフィグ内容"}</p>
          <div className="diff-view" style={{ flex: 1, maxHeight: "none" }}>
            {view === "diff"
              ? (diff ? parseDiff(diff) : <span style={{ color: "var(--color-muted)" }}>コミットを選択して差分表示</span>)
              : (content
                ? <pre style={{ whiteSpace: "pre-wrap", color: "#c9d1d9", fontSize: 12 }}>{content}</pre>
                : <span style={{ color: "var(--color-muted)" }}>コミットを選択してコンフィグを表示</span>)
            }
          </div>
        </div>
      </div>
    </div>
  );
}
