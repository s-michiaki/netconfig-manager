/** 構成図のノード（機器・非管理機器・雲・テキスト・グループ枠・図形・セグメント・中継点） */
import { createContext, memo, useContext } from "react";
import { Handle, NodeResizer, Position, type NodeProps } from "@xyflow/react";
import {
  STATE_LABELS, defaultIcon, formatTime,
  type AreaNode, type CloudNode, type DeviceIcon, type DeviceNode, type DeviceStatus, type LineStyle, type PointNode,
  type SegmentNode, type ShapeNode, type TextNode, type UnmanagedNode,
} from "./model";

export interface TopologyContextValue {
  statuses: Record<string, DeviceStatus>;
  editing: boolean;
}
export const TopologyContext = createContext<TopologyContextValue>({ statuses: {}, editing: false });

const STATE_COLOR = { ok: "#34d399", changed: "#fbbf24", failed: "#f87171", never: "#7c82a3" } as const;

const ICON_STYLE: Record<DeviceIcon, { bg: string; fg: string }> = {
  switch: { bg: "#22263a", fg: "#a5abc8" },
  l3switch: { bg: "#1e3a6e", fg: "#7aa9fa" },
  router: { bg: "#14303a", fg: "#5eead4" },
  firewall: { bg: "#3b1f14", fg: "#fb923c" },
  server: { bg: "#2a2140", fg: "#c4b5fd" },
  wireless: { bg: "#123326", fg: "#6ee7b7" },
  pc: { bg: "#22263a", fg: "#a5abc8" },
  printer: { bg: "#22263a", fg: "#a5abc8" },
  phone: { bg: "#22263a", fg: "#a5abc8" },
  camera: { bg: "#22263a", fg: "#a5abc8" },
  storage: { bg: "#2a2140", fg: "#c4b5fd" },
  other: { bg: "#22263a", fg: "#a5abc8" },
};

export function DeviceIconSvg({ icon, size = 20 }: { icon: DeviceIcon; size?: number }) {
  const common = {
    width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true,
  };
  switch (icon) {
    case "firewall":
      return <svg {...common}><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z" /><path d="M8 11h8M8 15h8M12 11v4" /></svg>;
    case "router":
      return <svg {...common}><circle cx="12" cy="12" r="8" /><path d="M8 12h8M13 9l3 3-3 3M11 9l-3 3 3 3" /></svg>;
    case "l3switch":
      return <svg {...common}><rect x="3" y="6" width="18" height="12" rx="2" /><path d="M7 10h10M14 8l3 2-3 2M7 14h10M10 12l-3 2 3 2" /></svg>;
    case "server":
      return <svg {...common}><rect x="5" y="3" width="14" height="8" rx="1.5" /><rect x="5" y="13" width="14" height="8" rx="1.5" /><path d="M9 7h.01M9 17h.01" /></svg>;
    case "wireless":
      return <svg {...common}><path d="M5 10a10 10 0 0 1 14 0M8 13.5a5.5 5.5 0 0 1 8 0" /><circle cx="12" cy="17" r="1.2" /><path d="M12 18v3" /></svg>;
    case "pc":
      return <svg {...common}><rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M9 20h6M12 16v4" /></svg>;
    case "printer":
      return <svg {...common}><path d="M7 9V3h10v6" /><rect x="3" y="9" width="18" height="8" rx="1.5" /><path d="M7 14h10v7H7z" /></svg>;
    case "phone":
      return <svg {...common}><rect x="6" y="2" width="12" height="20" rx="2" /><path d="M10 18h4" /></svg>;
    case "camera":
      return <svg {...common}><path d="M3 7h4l2-3h6l2 3h4v12H3z" /><circle cx="12" cy="13" r="3.5" /></svg>;
    case "storage":
      return <svg {...common}><ellipse cx="12" cy="5.5" rx="8" ry="2.5" /><path d="M4 5.5v13c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5v-13M4 12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5" /></svg>;
    case "other":
      return <svg {...common}><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" /><path d="M4 7.5l8 4.5 8-4.5M12 12v9" /></svg>;
    default:
      return <svg {...common}><rect x="3" y="8" width="18" height="8" rx="2" /><path d="M7 12h1M10 12h1M13 12h1M16 12h1" /></svg>;
  }
}

/** 上下左右の接続点。線は「ノードの縁どうし」を結ぶため、どの接続点から引いても同じ */
function Handles() {
  const { editing } = useContext(TopologyContext);
  const cls = `topo-handle${editing ? "" : " topo-handle-hidden"}`;
  return (
    <>
      <Handle id="t" type="source" position={Position.Top} className={cls} isConnectable={editing} />
      <Handle id="r" type="source" position={Position.Right} className={cls} isConnectable={editing} />
      <Handle id="b" type="source" position={Position.Bottom} className={cls} isConnectable={editing} />
      <Handle id="l" type="source" position={Position.Left} className={cls} isConnectable={editing} />
    </>
  );
}

export const DeviceNodeView = memo(function DeviceNodeView({ data, selected }: NodeProps<DeviceNode>) {
  const { statuses } = useContext(TopologyContext);
  const st = statuses[data.deviceId];
  const icon = data.icon ?? defaultIcon(st?.platform);
  const style = ICON_STYLE[icon];
  const state = st?.status ?? "never";
  return (
    <div
      className={`topo-device${selected ? " selected" : ""}${state === "failed" ? " failed" : ""}${st && !st.is_active ? " inactive" : ""}`}
      title={st?.last_message ?? undefined}
    >
      <Handles />
      <div className="topo-device-icon" style={{ background: style.bg, color: style.fg }}>
        <DeviceIconSvg icon={icon} />
      </div>
      <div className="topo-device-body">
        <div className="topo-device-name">{st?.name ?? "（読み込み中）"}</div>
        <div className="topo-device-host">{st?.hostname ?? ""}{st?.jump_host_name ? " · 踏み台経由" : ""}</div>
        <div className="topo-device-state" style={{ color: STATE_COLOR[state] }}>
          <span className="topo-dot" style={{ background: STATE_COLOR[state] }} />
          {STATE_LABELS[state]}
          {st?.last_collected_at && state !== "never" ? ` ${formatTime(st.last_collected_at)}` : ""}
          {st && !st.is_active ? "（無効）" : ""}
        </div>
      </div>
      {data.note && <div className="topo-node-note">{data.note}</div>}
    </div>
  );
});

/** 非管理機器: 登録していない機器（ISPルーター・ハブ・PC など）。収集状態は持たない */
export const UnmanagedNodeView = memo(function UnmanagedNodeView({ data, selected }: NodeProps<UnmanagedNode>) {
  const icon = data.icon ?? "other";
  return (
    <div className={`topo-device topo-unmanaged${selected ? " selected" : ""}`}>
      <Handles />
      <div className="topo-device-icon topo-unmanaged-icon">
        <DeviceIconSvg icon={icon} />
      </div>
      <div className="topo-device-body">
        <div className="topo-device-name">{data.label || "非管理機器"}</div>
        <div className="topo-device-host">{data.note ?? ""}</div>
        <div className="topo-device-state topo-unmanaged-tag">非管理</div>
      </div>
    </div>
  );
});

export const CloudNodeView = memo(function CloudNodeView({ data, selected }: NodeProps<CloudNode>) {
  const { editing } = useContext(TopologyContext);
  const color = data.color ?? "#7c82a3";
  return (
    <div className="topo-cloud" style={{ color }}>
      <NodeResizer isVisible={editing && selected} minWidth={80} minHeight={50} color="#4f8ef7" />
      <Handles />
      <svg viewBox="0 0 160 90" preserveAspectRatio="none" className="topo-cloud-shape" aria-hidden="true">
        <path
          d="M40 80 H122 A28 28 0 0 0 128 25 A36 36 0 0 0 62 18 A26 26 0 0 0 26 38 A22 22 0 0 0 40 80 Z"
          fill="#151824" stroke={selected ? "#4f8ef7" : color} strokeWidth={selected ? 2.5 : 1.8}
          strokeDasharray={selected ? undefined : "5 4"} vectorEffect="non-scaling-stroke"
        />
      </svg>
      <div className="topo-cloud-label">{data.label}</div>
    </div>
  );
});

const FONT_PX = { s: 12, m: 15, l: 20, xl: 28 } as const;

export const TextNodeView = memo(function TextNodeView({ data, selected }: NodeProps<TextNode>) {
  return (
    <div
      className={`topo-text${selected ? " selected" : ""}`}
      style={{ color: data.color ?? "#e4e6f0", fontSize: FONT_PX[data.fontSize ?? "m"] }}
    >
      {data.label || "テキスト"}
    </div>
  );
});

export const AreaNodeView = memo(function AreaNodeView({ data, selected }: NodeProps<AreaNode>) {
  const { editing } = useContext(TopologyContext);
  const color = data.color ?? "#4f8ef7";
  return (
    <div
      className="topo-area"
      style={{ borderColor: selected ? "#4f8ef7" : color, background: `${color}14` }}
    >
      <NodeResizer isVisible={editing && selected} minWidth={80} minHeight={60} color="#4f8ef7" />
      <div className="topo-area-label" style={{ color }}>{data.label}</div>
    </div>
  );
});

const DASH: Record<LineStyle, string | undefined> = { solid: undefined, dashed: "8 5", dotted: "1.5 4.5" };

/** 図形: 四角・角丸・楕円・ひし形。実際の大きさで描くので角丸や線の太さが歪まない */
export const ShapeNodeView = memo(function ShapeNodeView({ data, selected, width, height }: NodeProps<ShapeNode>) {
  const { editing } = useContext(TopologyContext);
  const w = width ?? 200;
  const h = height ?? 110;
  const color = selected ? "#4f8ef7" : data.color ?? "#7c82a3";
  const fill = data.fill ? `${data.fill}26` : "transparent";
  const common = {
    fill, stroke: color, strokeWidth: selected ? 2.5 : 1.8,
    strokeDasharray: DASH[data.borderStyle ?? "solid"], strokeLinecap: "round" as const,
  };
  const i = 1.5; // 線が切れないよう内側に描く
  let el;
  switch (data.shape) {
    case "ellipse":
      el = <ellipse cx={w / 2} cy={h / 2} rx={w / 2 - i} ry={h / 2 - i} {...common} />;
      break;
    case "diamond":
      el = <polygon points={`${w / 2},${i} ${w - i},${h / 2} ${w / 2},${h - i} ${i},${h / 2}`} {...common} />;
      break;
    default:
      el = <rect x={i} y={i} width={w - i * 2} height={h - i * 2} rx={data.shape === "rounded" ? 14 : 2} {...common} />;
  }
  return (
    <div className="topo-shape">
      <NodeResizer isVisible={editing && selected} minWidth={30} minHeight={20} color="#4f8ef7" />
      <Handles />
      <svg width={w} height={h} className="topo-shape-svg" aria-hidden="true">{el}</svg>
      <div className="topo-shape-label" style={{ color: data.color ?? "#e4e6f0", fontSize: FONT_PX[data.fontSize ?? "m"] }}>
        {data.label}
      </div>
    </div>
  );
});

/** セグメント: サブネット・VLAN などを表す太い線。長い方向に線を引き、つないだ線は線上に垂直に落ちる */
export const SegmentNodeView = memo(function SegmentNodeView({ data, selected, width, height }: NodeProps<SegmentNode>) {
  const { editing } = useContext(TopologyContext);
  const vertical = (height ?? 0) > (width ?? 0);
  const color = data.color ?? "#4f8ef7";
  return (
    <div className={`topo-segment${vertical ? " vertical" : ""}`}>
      <NodeResizer isVisible={editing && selected} minWidth={20} minHeight={20} color="#4f8ef7" />
      <Handles />
      <div className="topo-segment-bar" style={{ background: color, boxShadow: selected ? "0 0 0 3px #1e3a6e" : undefined }} />
      {data.label && <div className="topo-segment-label" style={{ color }}>{data.label}</div>}
    </div>
  );
});

/** 中継点: 線を折り曲げたり分岐させたりするための小さな点 */
export const PointNodeView = memo(function PointNodeView({ data, selected }: NodeProps<PointNode>) {
  return (
    <div className={`topo-point${selected ? " selected" : ""}`} style={{ background: data.color ?? "#5b6390" }}>
      <Handles />
    </div>
  );
});

export const nodeTypes = {
  device: DeviceNodeView,
  unmanaged: UnmanagedNodeView,
  cloud: CloudNodeView,
  text: TextNodeView,
  area: AreaNodeView,
  shape: ShapeNodeView,
  segment: SegmentNodeView,
  point: PointNodeView,
};
