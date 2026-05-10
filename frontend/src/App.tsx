import React, { useState } from "react";
import { Routes, Route, Link, useLocation, Navigate } from "react-router-dom";
import DevicesPage from "./pages/DevicesPage";
import CollectPage from "./pages/CollectPage";
import HistoryPage from "./pages/HistoryPage";
import TerminalPage from "./pages/TerminalPage";
import SchedulePage from "./pages/SchedulePage";
import "./index.css";

const NAV_ITEMS = [
  { path: "/devices", label: "デバイス管理", icon: "🖥" },
  { path: "/collect", label: "コンフィグ収集", icon: "↻" },
  { path: "/history", label: "世代管理", icon: "🕐" },
  { path: "/terminal", label: "ターミナル", icon: "⌨" },
  { path: "/schedules", label: "スケジュール", icon: "📅" },
];

export default function App() {
  const location = useLocation();

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-logo">⬡ NetConfig</span>
        </div>
        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="version-tag">v1.0.0 · RHEL 10</span>
        </div>
      </aside>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Navigate to="/devices" replace />} />
          <Route path="/devices" element={<DevicesPage />} />
          <Route path="/collect" element={<CollectPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/terminal" element={<TerminalPage />} />
          <Route path="/terminal/:deviceId" element={<TerminalPage />} />
          <Route path="/schedules" element={<SchedulePage />} />
        </Routes>
      </main>
    </div>
  );
}
