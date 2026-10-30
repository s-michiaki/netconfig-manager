/** 構成図: API の保存形式と React Flow のノード・エッジの相互変換 */
import { MarkerType, type Edge, type EdgeMarker, type Node } from "@xyflow/react";

export type DeviceIcon =
  | "switch" | "l3switch" | "router" | "firewall" | "server" | "wireless"
  | "pc" | "printer" | "phone" | "camera" | "storage" | "other";
export type FontSize = "s" | "m" | "l" | "xl";
export type LineStyle = "solid" | "dashed" | "dotted";
export type Arrow = "none" | "end" | "start" | "both";
export type Routing = "straight" | "step" | "curve";
export type LineWidth = "thin" | "normal" | "thick";
export type ShapeKind = "rect" | "rounded" | "ellipse" | "diamond";

/** 1つの構成図が持つ2枚のキャンバス */
export type ViewKind = "physical" | "logical";
export const VIEW_LABELS: Record<ViewKind, string> = { physical: "物理構成", logical: "論理構成" };

// ---- API の形式（backend/app/api/topology.py）
export interface ApiNode {
  id: string;
  type: "device" | "unmanaged" | "cloud" | "text" | "group" | "shape" | "segment" | "point";
  x: number;
  y: number;
  w?: number | null;
  h?: number | null;
  device_id?: string | null;
  label?: string | null;
  note?: string | null;
  color?: string | null;
  fill?: string | null;
  shape?: ShapeKind | null;
  border_style?: LineStyle | null;
  font_size?: FontSize | null;
  icon?: DeviceIcon | null;
}

export interface ApiEdge {
  id: string;
  source: string;
  target: string;
  source_port?: string | null;
  target_port?: string | null;
  label?: string | null;
  color?: string | null;
  line_style?: LineStyle | null;
  arrow?: Arrow | null;
  routing?: Routing | null;
  width?: LineWidth | null;
}

export interface TopologyData {
  nodes: ApiNode[];
  edges: ApiEdge[];
  viewport?: { x: number; y: number; zoom: number } | null;
}

export type CollectState = "ok" | "changed" | "failed" | "never";

export interface DeviceStatus {
  id: string;
  name: string;
  hostname: string;
  platform: string;
  is_active: boolean;
  jump_host_name: string | null;
  status: CollectState;
  last_collected_at: string | null;
  last_message: string | null;
}

export interface MapSummary {
  id: string;
  name: string;
  description: string | null;
  version: number;
  node_count: number;
  logical_node_count: number;
  device_count: number;
  updated_at: string | null;
  updated_by: string | null;
}

export interface MapDetail extends Omit<MapSummary, "node_count" | "logical_node_count" | "device_count"> {
  data: TopologyData; // 物理構成
  logical: TopologyData; // 論理構成
  devices: Record<string, DeviceStatus>;
}

// ---- React Flow 側のデータ
export type DeviceNodeData = { deviceId: string; icon?: DeviceIcon | null; note?: string | null };
/** 非管理機器（登録していない機器）。名前・補足は自由入力 */
export type UnmanagedNodeData = { label: string; note?: string | null; icon?: DeviceIcon | null };
export type CloudNodeData = { label: string; color?: string | null };
export type TextNodeData = { label: string; color?: string | null; fontSize?: FontSize | null };
export type AreaNodeData = { label: string; color?: string | null };
/** 図形（四角・角丸・楕円・ひし形）。中に文字を書ける */
export type ShapeNodeData = {
  label: string; shape: ShapeKind; color?: string | null; fill?: string | null;
  borderStyle?: LineStyle | null; fontSize?: FontSize | null;
};
/** セグメント（サブネット・VLAN などを表す線）。つないだ線は線上に垂直に落ちる */
export type SegmentNodeData = { label: string; color?: string | null };
/** 中継点（線の折り曲げ・分岐用の小さな点） */
export type PointNodeData = { color?: string | null };

export type DeviceNode = Node<DeviceNodeData, "device">;
export type UnmanagedNode = Node<UnmanagedNodeData, "unmanaged">;
export type CloudNode = Node<CloudNodeData, "cloud">;
export type TextNode = Node<TextNodeData, "text">;
export type AreaNode = Node<AreaNodeData, "area">; // React Flow 組み込みの "group" と名前が衝突しないよう area とする
export type ShapeNode = Node<ShapeNodeData, "shape">;
export type SegmentNode = Node<SegmentNodeData, "segment">;
export type PointNode = Node<PointNodeData, "point">;
export type TopoNode =
  | DeviceNode | UnmanagedNode | CloudNode | TextNode | AreaNode | ShapeNode | SegmentNode | PointNode;

export type LinkEdgeData = {
  sourcePort?: string | null;
  targetPort?: string | null;
  label?: string | null;
  color?: string | null;
  lineStyle?: LineStyle | null;
  arrow?: Arrow | null;
  routing?: Routing | null;
  width?: LineWidth | null;
  // 同じ2台の間に複数の線があるとき、重ならないよう少しずらす（描画用・保存しない）
  parallelIndex?: number;
  parallelCount?: number;
};
export type LinkEdge = Edge<LinkEdgeData, "link">;

export const DEVICE_NODE_SIZE = { w: 168, h: 64 };
export const DEFAULT_SIZE = {
  cloud: { w: 160, h: 90 },
  area: { w: 360, h: 220 },
  shape: { w: 200, h: 110 },
  segment: { w: 420, h: 24 },
};
export const POINT_SIZE = 14;

// 重なり順: グループ枠 < 図形 < 線 < 機器など
const Z = { area: -2, shape: -1 };

/** 装飾・線に使える色（ダーク背景で読める明るさに揃えている） */
export const PALETTE = ["#e4e6f0", "#7c82a3", "#4f8ef7", "#34d399", "#fbbf24", "#fb923c", "#f87171", "#c084fc"];
export const DEFAULT_EDGE_COLOR = "#5b6390";

export const ICON_LABELS: Record<DeviceIcon, string> = {
  switch: "スイッチ",
  l3switch: "L3スイッチ",
  router: "ルーター",
  firewall: "ファイアウォール",
  server: "サーバー",
  wireless: "無線AP",
  pc: "PC",
  printer: "プリンター",
  phone: "電話機",
  camera: "カメラ",
  storage: "ストレージ",
  other: "その他",
};

export const SHAPE_LABELS: Record<ShapeKind, string> = { rect: "四角", rounded: "角丸", ellipse: "楕円", diamond: "ひし形" };

export function defaultIcon(platform: string | undefined): DeviceIcon {
  if (!platform) return "switch";
  if (platform.startsWith("paloalto")) return "firewall";
  if (platform.startsWith("juniper")) return "router";
  return "switch";
}

const round = (v: number) => Math.round(v * 10) / 10;

export function toFlow(data: TopologyData): { nodes: TopoNode[]; edges: LinkEdge[] } {
  const nodes: TopoNode[] = data.nodes.map((n): TopoNode => {
    const position = { x: n.x, y: n.y };
    switch (n.type) {
      case "device":
        return { id: n.id, type: "device", position, data: { deviceId: n.device_id!, icon: n.icon ?? null, note: n.note } };
      case "unmanaged":
        return { id: n.id, type: "unmanaged", position, data: { label: n.label ?? "", note: n.note, icon: n.icon ?? null } };
      case "cloud":
        return {
          id: n.id, type: "cloud", position,
          width: n.w ?? DEFAULT_SIZE.cloud.w, height: n.h ?? DEFAULT_SIZE.cloud.h,
          data: { label: n.label ?? "", color: n.color },
        };
      case "text":
        return { id: n.id, type: "text", position, data: { label: n.label ?? "", color: n.color, fontSize: n.font_size } };
      case "group":
        return {
          id: n.id, type: "area", position, zIndex: Z.area,
          width: n.w ?? DEFAULT_SIZE.area.w, height: n.h ?? DEFAULT_SIZE.area.h,
          data: { label: n.label ?? "", color: n.color },
        };
      case "shape":
        return {
          id: n.id, type: "shape", position, zIndex: Z.shape,
          width: n.w ?? DEFAULT_SIZE.shape.w, height: n.h ?? DEFAULT_SIZE.shape.h,
          data: {
            label: n.label ?? "", shape: n.shape ?? "rounded", color: n.color, fill: n.fill,
            borderStyle: n.border_style, fontSize: n.font_size,
          },
        };
      case "segment":
        return {
          id: n.id, type: "segment", position,
          width: n.w ?? DEFAULT_SIZE.segment.w, height: n.h ?? DEFAULT_SIZE.segment.h,
          data: { label: n.label ?? "", color: n.color },
        };
      case "point":
        return { id: n.id, type: "point", position, data: { color: n.color } };
    }
  });
  const edges: LinkEdge[] = data.edges.map((e) => ({
    id: e.id, source: e.source, target: e.target, type: "link",
    data: {
      sourcePort: e.source_port, targetPort: e.target_port, label: e.label,
      color: e.color, lineStyle: e.line_style, arrow: e.arrow, routing: e.routing, width: e.width,
    },
  }));
  return { nodes, edges };
}

const nz = (s: string | null | undefined) => (s && s.trim() ? s : null);

export function fromFlow(
  nodes: TopoNode[], edges: LinkEdge[], viewport: { x: number; y: number; zoom: number }
): TopologyData {
  const size = (n: TopoNode, def: { w: number; h: number }) => ({
    w: round(n.width ?? n.measured?.width ?? def.w),
    h: round(n.height ?? n.measured?.height ?? def.h),
  });
  return {
    nodes: nodes.map((n): ApiNode => {
      const base = { id: n.id, x: round(n.position.x), y: round(n.position.y) };
      switch (n.type) {
        case "device":
          return { ...base, type: "device", device_id: n.data.deviceId, icon: n.data.icon ?? null, note: nz(n.data.note) };
        case "unmanaged":
          return { ...base, type: "unmanaged", label: n.data.label, note: nz(n.data.note), icon: n.data.icon ?? null };
        case "cloud":
          return { ...base, type: "cloud", ...size(n, DEFAULT_SIZE.cloud), label: n.data.label, color: n.data.color ?? null };
        case "text":
          return { ...base, type: "text", label: n.data.label, color: n.data.color ?? null, font_size: n.data.fontSize ?? null };
        case "area":
          return { ...base, type: "group", ...size(n, DEFAULT_SIZE.area), label: n.data.label, color: n.data.color ?? null };
        case "shape":
          return {
            ...base, type: "shape", ...size(n, DEFAULT_SIZE.shape), label: n.data.label, shape: n.data.shape,
            color: n.data.color ?? null, fill: n.data.fill ?? null, border_style: n.data.borderStyle ?? null,
            font_size: n.data.fontSize ?? null,
          };
        case "segment":
          return { ...base, type: "segment", ...size(n, DEFAULT_SIZE.segment), label: n.data.label, color: n.data.color ?? null };
        case "point":
          return { ...base, type: "point", color: n.data.color ?? null };
      }
    }),
    edges: edges.map((e) => ({
      id: e.id, source: e.source, target: e.target,
      source_port: nz(e.data?.sourcePort), target_port: nz(e.data?.targetPort), label: nz(e.data?.label),
      color: e.data?.color ?? null, line_style: e.data?.lineStyle ?? null,
      arrow: e.data?.arrow && e.data.arrow !== "none" ? e.data.arrow : null,
      routing: e.data?.routing && e.data.routing !== "straight" ? e.data.routing : null,
      width: e.data?.width && e.data.width !== "normal" ? e.data.width : null,
    })),
    viewport: { x: round(viewport.x), y: round(viewport.y), zoom: Math.round(viewport.zoom * 1000) / 1000 },
  };
}

/** 描画用の付加情報: 同じ2ノード間の線の番号（平行にずらす）と矢印 */
export function forRender(edges: LinkEdge[]): LinkEdge[] {
  const groups = new Map<string, string[]>();
  for (const e of edges) {
    const key = [e.source, e.target].sort().join("|");
    groups.set(key, [...(groups.get(key) ?? []), e.id]);
  }
  return edges.map((e) => {
    const ids = groups.get([e.source, e.target].sort().join("|"))!;
    const arrow = e.data?.arrow ?? "none";
    const color = e.selected ? "#4f8ef7" : e.data?.color ?? DEFAULT_EDGE_COLOR;
    const marker: EdgeMarker = { type: MarkerType.ArrowClosed, color, width: 16, height: 16 };
    return {
      ...e,
      markerEnd: arrow === "end" || arrow === "both" ? marker : undefined,
      markerStart: arrow === "start" || arrow === "both" ? { ...marker, orient: "auto-start-reverse" } : undefined,
      data: { ...e.data, parallelIndex: ids.indexOf(e.id), parallelCount: ids.length },
    };
  });
}

export const newId = (prefix: string) =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

export const STATE_LABELS: Record<CollectState, string> = {
  ok: "収集OK",
  changed: "変更あり",
  failed: "収集失敗",
  never: "未収集",
};

export function formatTime(iso: string | null): string {
  if (!iso) return "";
  // API の時刻はタイムゾーン無しの UTC
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + "Z");
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}/${d.getDate()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
