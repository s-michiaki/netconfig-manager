import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type ReactNode } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  Background, BackgroundVariant, ConnectionMode, Controls, MiniMap, ReactFlow, ReactFlowProvider,
  applyEdgeChanges, applyNodeChanges, useReactFlow,
  type Connection, type EdgeChange, type FinalConnectionState, type NodeChange,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { toBlob } from "html-to-image";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";
import {
  DEFAULT_SIZE, DEVICE_NODE_SIZE, ICON_LABELS, PALETTE, POINT_SIZE, SHAPE_LABELS, STATE_LABELS, VIEW_LABELS,
  defaultIcon, formatTime, forRender, fromFlow, newId, toFlow,
  type AreaNode, type Arrow, type CloudNode, type DeviceIcon, type DeviceNode, type DeviceStatus, type FontSize,
  type LineStyle, type LineWidth, type LinkEdge, type MapDetail, type MapSummary, type PointNode, type Routing,
  type SegmentNode, type ShapeKind, type ShapeNode, type TextNode, type TopoNode, type TopologyData,
  type UnmanagedNode, type ViewKind,
} from "../topology/model";
import { DeviceIconSvg, TopologyContext, nodeTypes } from "../topology/nodes";
import { edgeTypes } from "../topology/LinkEdge";

interface DeviceItem { id: string; name: string; hostname: string; platform: string; }

const STATUS_REFRESH_MS = 30_000;
const LAST_MAP_KEY = "topology:last-map";

function lastMap(): string | null {
  try {
    return localStorage.getItem(LAST_MAP_KEY);
  } catch {
    return null;
  }
}

// ============================================================ ページ（構成図の一覧・切り替え）

export default function TopologyPage() {
  const { mapId } = useParams();
  const [searchParams] = useSearchParams();
  // 物理構成 / 論理構成（URL の ?view=logical で切り替え。再読み込みしても同じ表示に戻る）
  const view: ViewKind = searchParams.get("view") === "logical" ? "logical" : "physical";
  const viewQuery = view === "logical" ? "?view=logical" : "";
  const navigate = useNavigate();
  const { can } = useAuth();
  const canWrite = can(PERM.TOPOLOGY_WRITE);
  const [maps, setMaps] = useState<MapSummary[] | null>(null);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState<null | { copyFrom?: MapSummary }>(null);
  const dirtyRef = useRef(false);

  const loadMaps = useCallback(async () => {
    try {
      setMaps((await api.get<MapSummary[]>("/topology/maps")).data);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    loadMaps();
    api.get<DeviceItem[]>("/devices/").then((r) => setDevices(r.data)).catch(() => {});
  }, [loadMaps]);

  // 構成図が指定されていなければ、前回開いていた構成図（無ければ先頭）を開く
  useEffect(() => {
    if (maps && maps.length && (!mapId || !maps.some((m) => m.id === mapId))) {
      const last = lastMap();
      navigate(`/topology/${maps.some((m) => m.id === last) ? last : maps[0].id}${viewQuery}`, { replace: true });
    }
  }, [maps, mapId, navigate, viewQuery]);

  useEffect(() => {
    if (!mapId) return;
    try {
      localStorage.setItem(LAST_MAP_KEY, mapId);
    } catch {
      /* 保存できなくても動作に影響なし */
    }
  }, [mapId]);

  // 未保存の変更がある状態でブラウザを閉じる・再読み込みするときは確認する
  useEffect(() => {
    const h = (e: BeforeUnloadEvent) => {
      if (dirtyRef.current) e.preventDefault();
    };
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, []);

  const switchMap = (id: string) => {
    if (id === mapId) return;
    if (dirtyRef.current && !window.confirm("保存していない変更があります。破棄して切り替えますか？")) return;
    dirtyRef.current = false;
    navigate(`/topology/${id}${viewQuery}`);
  };

  const switchView = (v: ViewKind) => {
    if (v === view || !mapId) return;
    if (dirtyRef.current && !window.confirm("保存していない変更があります。破棄して切り替えますか？")) return;
    dirtyRef.current = false;
    navigate(`/topology/${mapId}${v === "logical" ? "?view=logical" : ""}`);
  };

  const current = maps?.find((m) => m.id === mapId) ?? null;

  return (
    <div className="page">
      {creating && (
        <MapFormModal
          title={creating.copyFrom ? "構成図を複製" : "構成図を作成"}
          initial={{
            name: creating.copyFrom ? `${creating.copyFrom.name}（コピー）` : "",
            description: creating.copyFrom?.description ?? "",
          }}
          onClose={() => setCreating(null)}
          onSubmit={async (v) => {
            const r = await api.post<MapDetail>("/topology/maps", { ...v, copy_from: creating.copyFrom?.id ?? null });
            await loadMaps();
            dirtyRef.current = false;
            navigate(`/topology/${r.data.id}${viewQuery}`);
          }}
        />
      )}
      {maps === null ? (
        <div className="page-body">{error ? <p className="form-error">{error}</p> : "読み込み中..."}</div>
      ) : maps.length === 0 ? (
        <>
          <div className="page-header"><span className="page-title">構成図</span></div>
          <div className="page-body">
            <div className="topo-empty">
              <p>構成図はまだありません。</p>
              {canWrite ? (
                <>
                  <p className="topo-muted">登録済みの機器を配置して線で結び、拠点やフロアごとの簡易構成図を作れます。</p>
                  <button className="btn btn-primary" onClick={() => setCreating({})}>＋ 構成図を作成</button>
                </>
              ) : (
                <p className="topo-muted">構成図の作成はオペレーター以上の権限が必要です。</p>
              )}
            </div>
          </div>
        </>
      ) : current ? (
        <ReactFlowProvider key={`${current.id}:${view}`}>
          <Editor
            mapId={current.id}
            view={view}
            onSwitchView={switchView}
            maps={maps}
            devices={devices}
            canWrite={canWrite}
            onSwitch={switchMap}
            onCreate={() => setCreating({})}
            onDuplicate={() => setCreating({ copyFrom: current })}
            onChanged={loadMaps}
            onDeleted={async () => {
              dirtyRef.current = false;
              await loadMaps();
              navigate("/topology", { replace: true });
            }}
            onDirtyChange={(d) => (dirtyRef.current = d)}
          />
        </ReactFlowProvider>
      ) : null}
    </div>
  );
}

function MapFormModal({
  title, initial, onClose, onSubmit,
}: {
  title: string;
  initial: { name: string; description: string };
  onClose: () => void;
  onSubmit: (v: { name: string; description: string | null }) => Promise<void>;
}) {
  const [name, setName] = useState(initial.name);
  const [description, setDescription] = useState(initial.description);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      await onSubmit({ name: name.trim(), description: description.trim() || null });
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{title}</p>
        <div className="form-group">
          <label className="form-label" htmlFor="map-name">名前</label>
          <input id="map-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="例: 本社ネットワーク" autoFocus />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="map-desc">説明（任意）</label>
          <input id="map-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={submit} disabled={busy || !name.trim()}>保存</button>
        </div>
      </div>
    </div>
  );
}

// ============================================================ エディタ（1つの構成図）

interface EditorProps {
  mapId: string;
  view: ViewKind;
  onSwitchView: (v: ViewKind) => void;
  maps: MapSummary[];
  devices: DeviceItem[];
  canWrite: boolean;
  onSwitch: (id: string) => void;
  onCreate: () => void;
  onDuplicate: () => void;
  onChanged: () => void;
  onDeleted: () => void;
  onDirtyChange: (dirty: boolean) => void;
}

function Editor(props: EditorProps) {
  const {
    mapId, view, onSwitchView, maps, devices, canWrite, onSwitch, onCreate, onDuplicate, onChanged, onDeleted, onDirtyChange,
  } = props;
  // このエディタで扱うキャンバス（物理構成 / 論理構成）
  const docOf = useCallback((d: MapDetail): TopologyData => (view === "logical" ? d.logical : d.data), [view]);
  const rf = useReactFlow<TopoNode, LinkEdge>();
  const wrapper = useRef<HTMLDivElement>(null);
  const [detail, setDetail] = useState<MapDetail | null>(null);
  const [nodes, setNodes] = useState<TopoNode[]>([]);
  const [edges, setEdges] = useState<LinkEdge[]>([]);
  const [statuses, setStatuses] = useState<Record<string, DeviceStatus>>({});
  const [editing, setEditing] = useState(false);
  const [dirty, setDirtyState] = useState(false);
  const [snap, setSnap] = useState(true);
  const [error, setError] = useState("");
  const [conflict, setConflict] = useState(false);
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);
  const [editingMeta, setEditingMeta] = useState(false);

  // 親から渡される関数は描画のたびに作り直されるため、ref 経由で呼ぶ（読み込みが繰り返されないように）
  const onDirtyRef = useRef(onDirtyChange);
  onDirtyRef.current = onDirtyChange;
  const setDirty = useCallback((d: boolean) => {
    setDirtyState(d);
    onDirtyRef.current(d);
  }, []);

  const applyDetail = useCallback((d: MapDetail) => {
    const flow = toFlow(docOf(d));
    setDetail(d);
    setNodes(flow.nodes);
    setEdges(flow.edges);
    setStatuses(d.devices);
    setDirty(false);
    setConflict(false);
  }, [setDirty, docOf]);

  const load = useCallback(async () => {
    setError("");
    try {
      applyDetail((await api.get<MapDetail>(`/topology/maps/${mapId}`)).data);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [mapId, applyDetail]);

  useEffect(() => {
    load();
  }, [load]);

  // 収集状態を定期的に更新する（配置は上書きしない）
  const refreshStatus = useCallback(async () => {
    try {
      const r = await api.get<Record<string, DeviceStatus>>(`/topology/maps/${mapId}/status`);
      setStatuses((prev) => ({ ...prev, ...r.data }));
    } catch {
      /* 一時的な失敗は無視 */
    }
  }, [mapId]);
  useEffect(() => {
    const t = window.setInterval(refreshStatus, STATUS_REFRESH_MS);
    return () => window.clearInterval(t);
  }, [refreshStatus]);

  useEffect(() => {
    if (!notice) return;
    const t = window.setTimeout(() => setNotice(""), 4000);
    return () => window.clearTimeout(t);
  }, [notice]);

  // ---------------------------------------------------------------- 変更
  const onNodesChange = useCallback((changes: NodeChange<TopoNode>[]) => {
    setNodes((nds) => applyNodeChanges(changes, nds));
    // 選択や初回の大きさ計測は「変更」に数えない
    if (changes.some((c) => c.type === "position" || c.type === "remove" || c.type === "add"
      || (c.type === "dimensions" && c.resizing !== undefined))) {
      setDirty(true);
    }
  }, [setDirty]);

  const onEdgesChange = useCallback((changes: EdgeChange<LinkEdge>[]) => {
    setEdges((eds) => applyEdgeChanges(changes, eds));
    if (changes.some((c) => c.type === "remove" || c.type === "add")) setDirty(true);
  }, [setDirty]);

  const onConnect = useCallback((c: Connection) => {
    if (!c.source || !c.target || c.source === c.target) return;
    // つないだ線を選択状態にして、すぐポート名を入力できるようにする
    const edge: LinkEdge = { id: newId("e"), source: c.source, target: c.target, type: "link", data: {}, selected: true };
    setNodes((nds) => nds.map((n) => (n.selected ? { ...n, selected: false } : n)));
    setEdges((eds) => [...eds.map((e) => (e.selected ? { ...e, selected: false } : e)), edge]);
    setDirty(true);
  }, [setDirty]);

  // 線をつなげられるノード（テキスト・グループ枠は不可）
  const CONNECTABLE = useMemo(() => new Set(["device", "unmanaged", "cloud", "shape", "segment", "point"]), []);

  // React Flow は相手の接続点 ● の近くで離したときだけ線をつなぐ。
  // 相手の箱の上ならどこで離してもつながるように、離した位置のノードを探して接続する
  const onConnectEnd = useCallback((event: MouseEvent | TouchEvent, state: FinalConnectionState) => {
    if (state.isValid || !state.fromNode) return;
    const pt = "changedTouches" in event ? event.changedTouches[0] : event;
    if (!pt) return;
    const el = document.elementFromPoint(pt.clientX, pt.clientY)?.closest(".react-flow__node");
    const targetId = el?.getAttribute("data-id");
    if (!targetId || targetId === state.fromNode.id) return;
    if (!CONNECTABLE.has(rf.getNode(targetId)?.type ?? "")) return;
    onConnect({ source: state.fromNode.id, target: targetId, sourceHandle: null, targetHandle: null });
  }, [CONNECTABLE, onConnect, rf]);

  const updateNode = useCallback((id: string, patch: Record<string, unknown>) => {
    setNodes((nds) => nds.map((n) => (n.id === id ? ({ ...n, data: { ...n.data, ...patch } } as TopoNode) : n)));
    setDirty(true);
  }, [setDirty]);

  const updateEdge = useCallback((id: string, patch: Partial<NonNullable<LinkEdge["data"]>>) => {
    setEdges((eds) => eds.map((e) => (e.id === id ? { ...e, data: { ...e.data, ...patch } } : e)));
    setDirty(true);
  }, [setDirty]);

  const removeSelected = useCallback(() => {
    const ids = new Set(nodes.filter((n) => n.selected).map((n) => n.id));
    setNodes((nds) => nds.filter((n) => !n.selected));
    setEdges((eds) => eds.filter((e) => !e.selected && !ids.has(e.source) && !ids.has(e.target)));
    setDirty(true);
  }, [nodes, setDirty]);

  const viewCenter = () => {
    const rect = wrapper.current!.getBoundingClientRect();
    return rf.screenToFlowPosition({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 });
  };

  const addNode = (node: TopoNode) => {
    setNodes((nds) => [...nds.map((n) => (n.selected ? { ...n, selected: false } : n)), { ...node, selected: true }]);
    setEdges((eds) => eds.map((e) => (e.selected ? { ...e, selected: false } : e)));
    setDirty(true);
  };

  const addDecoration = (kind: AddKind, shape: ShapeKind = "rounded") => {
    const c = viewCenter();
    if (kind === "shape") {
      const { w, h } = DEFAULT_SIZE.shape;
      addNode({
        id: newId("s"), type: "shape", position: { x: c.x - w / 2, y: c.y - h / 2 }, width: w, height: h, zIndex: -1,
        data: { label: "", shape, color: null, fill: null, borderStyle: null },
      } as ShapeNode);
    } else if (kind === "segment") {
      const { w, h } = DEFAULT_SIZE.segment;
      addNode({
        id: newId("sg"), type: "segment", position: { x: c.x - w / 2, y: c.y - h / 2 }, width: w, height: h,
        data: { label: "VLAN / サブネット" },
      } as SegmentNode);
    } else if (kind === "point") {
      addNode({
        id: newId("p"), type: "point", position: { x: c.x - POINT_SIZE / 2, y: c.y - POINT_SIZE / 2 }, data: {},
      } as PointNode);
    } else if (kind === "unmanaged") {
      addNode({
        id: newId("u"), type: "unmanaged",
        position: { x: c.x - DEVICE_NODE_SIZE.w / 2, y: c.y - DEVICE_NODE_SIZE.h / 2 },
        data: { label: "非管理機器", note: "", icon: null },
      } as UnmanagedNode);
    } else if (kind === "cloud") {
      const { w, h } = DEFAULT_SIZE.cloud;
      addNode({ id: newId("c"), type: "cloud", position: { x: c.x - w / 2, y: c.y - h / 2 }, width: w, height: h, data: { label: "Internet" } } as CloudNode);
    } else if (kind === "text") {
      addNode({ id: newId("t"), type: "text", position: { x: c.x - 40, y: c.y - 12 }, data: { label: "テキスト", fontSize: "m" } } as TextNode);
    } else {
      const { w, h } = DEFAULT_SIZE.area;
      addNode({ id: newId("g"), type: "area", position: { x: c.x - w / 2, y: c.y - h / 2 }, width: w, height: h, zIndex: -2, data: { label: "グループ" } } as AreaNode);
    }
  };

  const placedDeviceIds = useMemo(
    () => new Set(nodes.filter((n): n is DeviceNode => n.type === "device").map((n) => n.data.deviceId)),
    [nodes]
  );

  const addDevice = async (deviceId: string, pos?: { x: number; y: number }) => {
    if (placedDeviceIds.has(deviceId)) return;
    const c = pos ?? viewCenter();
    addNode({
      id: newId("d"), type: "device",
      position: { x: c.x - DEVICE_NODE_SIZE.w / 2, y: c.y - DEVICE_NODE_SIZE.h / 2 },
      data: { deviceId },
    } as DeviceNode);
    if (!statuses[deviceId]) {
      try {
        const r = await api.post<Record<string, DeviceStatus>>("/topology/device-status", [deviceId]);
        setStatuses((prev) => ({ ...prev, ...r.data }));
      } catch {
        /* 次の定期更新で取得される */
      }
    }
  };

  const onDragOver = (e: DragEvent) => {
    if (!editing) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
  };
  const onDrop = (e: DragEvent) => {
    if (!editing) return;
    e.preventDefault();
    const id = e.dataTransfer.getData("application/x-netconfig-device");
    if (id) addDevice(id, rf.screenToFlowPosition({ x: e.clientX, y: e.clientY }));
  };

  // ---------------------------------------------------------------- 保存・破棄・出力
  const save = async () => {
    if (!detail) return;
    setSaving(true);
    setError("");
    try {
      // 表示中のキャンバスだけを保存する（もう一方は変わらない）
      const r = await api.put<MapDetail>(`/topology/maps/${mapId}`, {
        version: detail.version,
        [view === "logical" ? "logical" : "data"]: fromFlow(nodes, edges, rf.getViewport()),
      });
      applyDetail(r.data);
      setNotice("保存しました");
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
      if ((e as { response?: { status?: number } }).response?.status === 409) setConflict(true);
    } finally {
      setSaving(false);
    }
  };

  const discard = () => {
    if (dirty && !window.confirm("保存していない変更を破棄して、保存済みの状態に戻しますか？")) return;
    load();
  };

  const deleteMap = async () => {
    if (!detail || !window.confirm(`構成図「${detail.name}」を削除しますか？（機器の登録は削除されません）`)) return;
    try {
      await api.delete(`/topology/maps/${mapId}`);
      onDeleted();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const exportPng = async () => {
    if (!detail || !nodes.length || !wrapper.current) return;
    // 選択枠を画像に含めない
    setNodes((nds) => nds.map((n) => (n.selected ? { ...n, selected: false } : n)));
    setEdges((eds) => eds.map((e) => (e.selected ? { ...e, selected: false } : e)));
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const b = rf.getNodesBounds(nodes);
    // セグメントの名前や機器の補足はノードの外側にはみ出して描くため、余白を広めに取る
    const padX = 140;
    const padY = 60;
    const zoom = Math.min(1, 6000 / Math.max(b.width + padX * 2, b.height + padY * 2));
    const width = Math.ceil((b.width + padX * 2) * zoom);
    const height = Math.ceil((b.height + padY * 2) * zoom);
    const el = wrapper.current.querySelector<HTMLElement>(".react-flow__viewport");
    if (!el) return;
    try {
      const blob = await toBlob(el, {
        backgroundColor: "#0f1117",
        // Web フォント（外部CSS）の埋め込みはしない（閉じたネットワークでは取得できず、エラーになるだけのため）
        skipFonts: true,
        width, height, pixelRatio: 2,
        style: {
          width: `${width}px`, height: `${height}px`,
          transform: `translate(${(padX - b.x) * zoom}px, ${(padY - b.y) * zoom}px) scale(${zoom})`,
        },
        filter: (n) => !(n instanceof HTMLElement && (n.classList.contains("react-flow__handle")
          || n.classList.contains("react-flow__resize-control"))),
      });
      if (!blob) throw new Error("画像を生成できませんでした");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${detail.name.replace(/[\\/:*?"<>|]/g, "_")}_${VIEW_LABELS[view]}.png`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch (e) {
      setError(`画像の出力に失敗しました: ${errorMessage(e)}`);
    }
  };

  const toggleEditing = () => {
    if (editing && dirty && !window.confirm("保存していない変更があります。破棄して閲覧モードに戻りますか？")) return;
    if (editing && dirty) load();
    setEditing(!editing);
  };

  const renderEdges = useMemo(() => forRender(edges), [edges]);
  const ctx = useMemo(() => ({ statuses, editing }), [statuses, editing]);
  const selNodes = nodes.filter((n) => n.selected);
  const selEdges = edges.filter((e) => e.selected);

  if (!detail) {
    return <div className="page-body">{error ? <p className="form-error">{error}</p> : "読み込み中..."}</div>;
  }

  return (
    <>
      {editingMeta && (
        <MapFormModal
          title="構成図の名前・説明"
          initial={{ name: detail.name, description: detail.description ?? "" }}
          onClose={() => setEditingMeta(false)}
          onSubmit={async (v) => {
            const r = await api.put<MapDetail>(`/topology/maps/${mapId}`, { version: detail.version, ...v });
            // 配置の編集内容は保ったまま、名前と version だけ反映する
            setDetail((d) => (d ? { ...d, name: r.data.name, description: r.data.description, version: r.data.version,
              updated_at: r.data.updated_at, updated_by: r.data.updated_by } : d));
            onChanged();
          }}
        />
      )}
      <div className="page-header topo-header">
        <div className="topo-header-left">
          <span className="page-title">構成図</span>
          <select className="topo-map-select" value={mapId} onChange={(e) => onSwitch(e.target.value)} aria-label="構成図を選択">
            {maps.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
          </select>
          <div className="topo-view-tabs" role="tablist" aria-label="表示する構成">
            {(["physical", "logical"] as const).map((v) => (
              <button
                key={v} role="tab" aria-selected={view === v}
                className={`topo-view-tab${view === v ? " active" : ""}`} onClick={() => onSwitchView(v)}
              >
                {VIEW_LABELS[v]}
              </button>
            ))}
          </div>
          {canWrite && !editing && (
            <>
              <button className="btn" onClick={onCreate}>＋ 新規</button>
              <button className="btn" onClick={onDuplicate}>複製</button>
              <button className="btn" onClick={() => setEditingMeta(true)}>名前変更</button>
              <button className="btn btn-danger" onClick={deleteMap}>削除</button>
            </>
          )}
        </div>
        <div className="topo-header-right">
          {notice && <span className="topo-notice">{notice}</span>}
          {editing && (
            <label className="form-check">
              <input type="checkbox" checked={snap} onChange={(e) => setSnap(e.target.checked)} />
              グリッドに吸着
            </label>
          )}
          <button className="btn" onClick={exportPng} disabled={!nodes.length}>PNG出力</button>
          {canWrite && (
            editing ? (
              <>
                {dirty && <span className="topo-dirty">未保存の変更あり</span>}
                <button className="btn" onClick={discard} disabled={!dirty}>元に戻す</button>
                <button className="btn" onClick={toggleEditing}>編集を終了</button>
                <button className="btn btn-primary" onClick={save} disabled={saving || !dirty}>
                  {saving ? "保存中..." : "保存"}
                </button>
              </>
            ) : (
              <button className="btn btn-primary" onClick={toggleEditing}>編集</button>
            )
          )}
        </div>
      </div>
      {error && (
        <div className="topo-error">
          {error}
          {conflict && <button className="btn" onClick={load}>再読み込み（自分の変更は破棄されます）</button>}
          <button className="link-btn" onClick={() => setError("")}>閉じる</button>
        </div>
      )}
      <div className="topo-main">
        <div className={`topo-canvas${editing ? " editing" : ""}`} ref={wrapper} onDragOver={onDragOver} onDrop={onDrop}>
          <TopologyContext.Provider value={ctx}>
            <ReactFlow<TopoNode, LinkEdge>
              nodes={nodes}
              edges={renderEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onConnectEnd={onConnectEnd}
              isValidConnection={(c) => c.source !== c.target}
              connectionMode={ConnectionMode.Loose}
              connectionRadius={30}
              nodesDraggable={editing}
              nodesConnectable={editing}
              edgesReconnectable={false}
              elementsSelectable
              deleteKeyCode={editing ? ["Delete", "Backspace"] : null}
              multiSelectionKeyCode={["Shift", "Control", "Meta"]}
              snapToGrid={editing && snap}
              snapGrid={[10, 10]}
              defaultViewport={docOf(detail).viewport ?? undefined}
              fitView={!docOf(detail).viewport}
              fitViewOptions={{ padding: 0.2, maxZoom: 1.2 }}
              minZoom={0.1}
              maxZoom={3}
              colorMode="dark"
              onlyRenderVisibleElements={false}
            >
              <Background variant={BackgroundVariant.Dots} gap={20} size={1.2} color="#2a2f45" />
              <Controls showInteractive={false} />
              <MiniMap
                pannable zoomable
                nodeColor={(n) => (n.type === "area" || n.type === "shape" ? "transparent" : n.type === "device" ? "#4f8ef7"
                  : n.type === "unmanaged" ? "#5b6390" : n.type === "segment" ? "#34d399" : "#3a4060")}
                nodeStrokeColor={(n) => (n.type === "area" || n.type === "shape" ? "#4a5178" : "transparent")}
                maskColor="rgba(15,17,23,0.7)"
                style={{ background: "#1a1d27", width: 160, height: 110 }}
              />
            </ReactFlow>
          </TopologyContext.Provider>
          {!nodes.length && (
            <div className="topo-canvas-hint">
              {canWrite
                ? editing
                  ? view === "logical"
                    ? "右の一覧から機器・図形・セグメントを配置してください"
                    : "右の一覧から機器をドラッグして配置してください"
                  : `「編集」を押すと${VIEW_LABELS[view]}を描けます`
                : "この構成図にはまだ何も配置されていません"}
            </div>
          )}
        </div>
        <aside className="topo-panel">
          {selNodes.length + selEdges.length > 1 ? (
            <MultiPanel count={selNodes.length + selEdges.length} editing={editing} onDelete={removeSelected} />
          ) : selNodes.length === 1 ? (
            selNodes[0].type === "device" ? (
              <DevicePanel
                node={selNodes[0]} status={statuses[selNodes[0].data.deviceId]} editing={editing}
                onChange={(p) => updateNode(selNodes[0].id, p)} onRemove={removeSelected}
                onCollected={() => window.setTimeout(refreshStatus, 15_000)} notify={setNotice}
              />
            ) : selNodes[0].type === "shape" || selNodes[0].type === "segment" || selNodes[0].type === "point" ? (
              <DrawPanel node={selNodes[0]} editing={editing} onChange={(p) => updateNode(selNodes[0].id, p)} onRemove={removeSelected} />
            ) : selNodes[0].type === "unmanaged" ? (
              <UnmanagedPanel node={selNodes[0]} editing={editing} onChange={(p) => updateNode(selNodes[0].id, p)} onRemove={removeSelected} />
            ) : (
              <DecorationPanel node={selNodes[0]} editing={editing} onChange={(p) => updateNode(selNodes[0].id, p)} onRemove={removeSelected} />
            )
          ) : selEdges.length === 1 ? (
            <EdgePanel
              edge={selEdges[0]} nodes={nodes} statuses={statuses} editing={editing}
              onChange={(p) => updateEdge(selEdges[0].id, p)} onRemove={removeSelected}
            />
          ) : (
            <MapInfoPanel detail={detail} view={view} editing={editing} canWrite={canWrite} />
          )}
          {editing && (
            <Palette
              view={view} devices={devices} placed={placedDeviceIds}
              onAddDevice={(id) => addDevice(id)} onAddDecoration={addDecoration}
            />
          )}
        </aside>
      </div>
    </>
  );
}

// ============================================================ サイドパネル

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="topo-section">
      <p className="section-label">{title}</p>
      {children}
    </section>
  );
}

const STATE_BADGE = { ok: "badge-success", changed: "badge-warning", failed: "badge-danger", never: "badge-neutral" } as const;

function MapInfoPanel({
  detail, view, editing, canWrite,
}: { detail: MapDetail; view: ViewKind; editing: boolean; canWrite: boolean }) {
  return (
    <>
      <Section title={`構成図（${VIEW_LABELS[view]}）`}>
        <div className="topo-map-name">{detail.name}</div>
        {detail.description && <p className="topo-muted">{detail.description}</p>}
        <p className="topo-muted topo-small">
          最終更新 {formatTime(detail.updated_at)}{detail.updated_by ? `（${detail.updated_by}）` : ""}
        </p>
      </Section>
      <Section title="凡例（最後の収集結果）">
        <ul className="topo-legend">
          {(["ok", "changed", "failed", "never"] as const).map((s) => (
            <li key={s}><span className={`badge ${STATE_BADGE[s]}`}>{STATE_LABELS[s]}</span>
              <span className="topo-muted topo-small">
                {{ ok: "前回の収集は成功、変更なし", changed: "前回の収集で新しい世代を保存", failed: "前回の収集に失敗", never: "まだ収集していない" }[s]}
              </span>
            </li>
          ))}
        </ul>
        <p className="topo-muted topo-small">状態は30秒ごとに自動更新されます。</p>
      </Section>
      <Section title="操作">
        <ul className="topo-help">
          <li>機器をクリック: 詳細・ターミナル・変更履歴</li>
          <li>ホイール: 拡大縮小 / 背景をドラッグ: 移動</li>
          {editing ? (
            <>
              <li>機器の縁の ● から別の機器へドラッグ: 線を引く</li>
              {view === "logical" && (
                <>
                  <li>セグメントへ線を引くと、線上に垂直につながります</li>
                  <li>線を曲げたい・分岐させたいときは「中継点」を経由します</li>
                </>
              )}
              <li>Shift + ドラッグ: 範囲選択</li>
              <li>Delete: 選択したものを削除</li>
            </>
          ) : canWrite ? (
            <li>右上の「編集」で配置・線の追加ができます</li>
          ) : null}
        </ul>
      </Section>
    </>
  );
}

function DevicePanel({
  node, status, editing, onChange, onRemove, onCollected, notify,
}: {
  node: DeviceNode; status?: DeviceStatus; editing: boolean;
  onChange: (p: Record<string, unknown>) => void; onRemove: () => void; onCollected: () => void; notify: (s: string) => void;
}) {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [busy, setBusy] = useState(false);
  const icon = node.data.icon ?? defaultIcon(status?.platform);
  const collect = async () => {
    setBusy(true);
    try {
      await api.post(`/devices/${node.data.deviceId}/collect`);
      notify("収集を開始しました");
      onCollected();
    } catch (e) {
      notify(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  if (!status) return <Section title="選択中の機器"><p className="topo-muted">読み込み中...</p></Section>;
  return (
    <Section title="選択中の機器">
      <div className="topo-dev-head">
        <span className="topo-dev-icon"><DeviceIconSvg icon={icon} size={22} /></span>
        <div>
          <div className="topo-map-name">{status.name}</div>
          <div className="topo-muted topo-small">{status.platform} · {status.hostname}</div>
        </div>
      </div>
      <dl className="topo-kv">
        <dt>最後の収集</dt>
        <dd>
          <span className={`badge ${STATE_BADGE[status.status]}`}>{STATE_LABELS[status.status]}</span>{" "}
          {formatTime(status.last_collected_at)}
        </dd>
        {status.status === "failed" && status.last_message && (<><dt>エラー</dt><dd className="topo-err-msg">{status.last_message}</dd></>)}
        <dt>接続経路</dt><dd>{status.jump_host_name ? `踏み台経由（${status.jump_host_name}）` : "直接接続"}</dd>
        {!editing && node.data.note && (<><dt>補足</dt><dd>{node.data.note}</dd></>)}
        {can(PERM.COMPLIANCE_READ) && (
          <>
            <dt>コンプライアンス</dt>
            <dd>
              {status.violations > 0 ? (
                <button className="link-btn topo-err-msg" onClick={() => navigate(`/compliance?device=${status.id}`)}>
                  違反 {status.violations}件（最も重いもの: {{ high: "高", medium: "中", low: "低" }[status.violation_severity ?? "low"]}）
                </button>
              ) : "違反なし"}
            </dd>
          </>
        )}
        {!status.is_active && (<><dt>状態</dt><dd>無効（一括・スケジュール収集の対象外）</dd></>)}
      </dl>
      <div className="topo-actions">
        {can(PERM.TERMINAL) && (
          <button className="btn btn-primary" onClick={() => navigate(`/terminal/${status.id}`)}>ターミナルを開く</button>
        )}
        <div className="topo-actions-row">
          {can(PERM.CONFIG_READ) && (
            <button className="btn" onClick={() => navigate(`/history?device=${status.id}`)}>変更履歴</button>
          )}
          {can(PERM.COLLECT) && <button className="btn" onClick={collect} disabled={busy}>今すぐ収集</button>}
        </div>
      </div>
      {editing && (
        <>
          <div className="form-group" style={{ marginTop: 14 }}>
            <label className="form-label" htmlFor="dev-note">補足（任意・機器の下に表示）</label>
            <input id="dev-note" value={node.data.note ?? ""} maxLength={200} placeholder="例: Lo0 10.255.0.1 / コアL3"
              onChange={(e) => onChange({ note: e.target.value })} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="dev-icon">アイコン</label>
            <select id="dev-icon" value={node.data.icon ?? ""} onChange={(e) => onChange({ icon: (e.target.value || null) as DeviceIcon | null })}>
              <option value="">自動（{ICON_LABELS[defaultIcon(status.platform)]}）</option>
              {Object.entries(ICON_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <button className="btn btn-danger" onClick={onRemove}>構成図から外す</button>
          <p className="topo-muted topo-small" style={{ marginTop: 6 }}>機器の登録は削除されません。</p>
        </>
      )}
    </Section>
  );
}

function ColorPicker({
  value, onChange, label, allowNone = false,
}: { value?: string | null; onChange: (c: string) => void; label: string; allowNone?: boolean }) {
  return (
    <div className="form-group">
      <span className="form-label">{label}</span>
      <div className="topo-swatches" role="radiogroup" aria-label={label}>
        {allowNone && (
          <button
            type="button" role="radio" aria-checked={!value} aria-label="なし" title="なし"
            className={`topo-swatch topo-swatch-none${!value ? " active" : ""}`} onClick={() => onChange("")}
          />
        )}
        {PALETTE.map((c) => (
          <button
            key={c} type="button" role="radio" aria-checked={value === c} aria-label={c}
            className={`topo-swatch${value === c ? " active" : ""}`} style={{ background: c }}
            onClick={() => onChange(c)}
          />
        ))}
      </div>
    </div>
  );
}

const DECOR_TITLE = {
  unmanaged: "非管理機器", cloud: "雲", text: "テキスト", area: "グループ枠", shape: "図形", segment: "セグメント", point: "中継点",
} as const;

type AddKind = "unmanaged" | "cloud" | "text" | "area" | "shape" | "segment" | "point";

const FILL_NONE = "";

/** 作図要素（図形・セグメント・中継点）のパネル */
function DrawPanel({
  node, editing, onChange, onRemove,
}: { node: ShapeNode | SegmentNode | PointNode; editing: boolean; onChange: (p: Record<string, unknown>) => void; onRemove: () => void }) {
  const title = node.type === "shape" ? `${SHAPE_LABELS[node.data.shape]}（図形）` : DECOR_TITLE[node.type];
  if (!editing) {
    const label = node.type === "point" ? "" : node.data.label;
    return <Section title={`選択中: ${title}`}>{label ? <p style={{ whiteSpace: "pre-wrap" }}>{label}</p> : null}</Section>;
  }
  return (
    <Section title={`選択中: ${title}`}>
      {node.type !== "point" && (
        <div className="form-group">
          <label className="form-label" htmlFor="draw-label">{node.type === "segment" ? "名前（VLAN・サブネットなど）" : "文字"}</label>
          <textarea id="draw-label" rows={2} value={node.data.label} maxLength={500}
            placeholder={node.type === "segment" ? "例: VLAN10 192.168.10.0/24" : "例: OSPF Area 0 / DMZ"}
            onChange={(e) => onChange({ label: e.target.value })} />
        </div>
      )}
      {node.type === "shape" && (
        <>
          <div className="topo-form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="draw-shape">形</label>
              <select id="draw-shape" value={node.data.shape} onChange={(e) => onChange({ shape: e.target.value as ShapeKind })}>
                {Object.entries(SHAPE_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="draw-border">枠線</label>
              <select id="draw-border" value={node.data.borderStyle ?? "solid"} onChange={(e) => onChange({ borderStyle: e.target.value as LineStyle })}>
                <option value="solid">実線</option><option value="dashed">破線</option><option value="dotted">点線</option>
              </select>
            </div>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="draw-size">文字の大きさ</label>
            <select id="draw-size" value={node.data.fontSize ?? "m"} onChange={(e) => onChange({ fontSize: e.target.value as FontSize })}>
              <option value="s">小</option><option value="m">中</option><option value="l">大</option><option value="xl">特大</option>
            </select>
          </div>
          <ColorPicker label="塗り" value={node.data.fill ?? FILL_NONE} allowNone
            onChange={(fill) => onChange({ fill: fill || null })} />
        </>
      )}
      <ColorPicker label={node.type === "shape" ? "枠線・文字の色" : "色"} value={node.data.color} onChange={(color) => onChange({ color })} />
      {node.type === "segment" && (
        <p className="topo-muted topo-small">端をドラッグして長さを変えられます（縦長にすると縦のセグメントになります）。</p>
      )}
      {node.type === "shape" && <p className="topo-muted topo-small">選択中に四隅をドラッグすると大きさを変えられます。</p>}
      {node.type === "point" && <p className="topo-muted topo-small">線の折り曲げ・分岐に使います。縁の ● から線を引けます。</p>}
      <button className="btn btn-danger" onClick={onRemove} style={{ marginTop: 8 }}>削除</button>
    </Section>
  );
}

function UnmanagedPanel({
  node, editing, onChange, onRemove,
}: { node: UnmanagedNode; editing: boolean; onChange: (p: Record<string, unknown>) => void; onRemove: () => void }) {
  const icon = node.data.icon ?? "other";
  const head = (
    <div className="topo-dev-head">
      <span className="topo-dev-icon"><DeviceIconSvg icon={icon} size={22} /></span>
      <div>
        <div className="topo-map-name">{node.data.label || "非管理機器"}</div>
        <div className="topo-muted topo-small">{node.data.note || "補足なし"}</div>
      </div>
    </div>
  );
  if (!editing) {
    return (
      <Section title="選択中: 非管理機器">
        {head}
        <p className="topo-muted topo-small" style={{ marginTop: 10 }}>
          この構成図にだけ描いている機器です（デバイス管理には登録されていないため、収集・ターミナルの対象外）。
        </p>
      </Section>
    );
  }
  return (
    <Section title="選択中: 非管理機器">
      <div className="form-group">
        <label className="form-label" htmlFor="um-name">名前</label>
        <input id="um-name" value={node.data.label} maxLength={500} placeholder="例: ISPルーター / 2F ハブ"
          onChange={(e) => onChange({ label: e.target.value })} />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="um-note">補足（任意）</label>
        <input id="um-note" value={node.data.note ?? ""} maxLength={200} placeholder="例: 192.168.1.1 / 型番 / 管理会社"
          onChange={(e) => onChange({ note: e.target.value })} />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="um-icon">アイコン</label>
        <select id="um-icon" value={icon} onChange={(e) => onChange({ icon: e.target.value as DeviceIcon })}>
          {Object.entries(ICON_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      </div>
      <p className="topo-muted topo-small">縁の ● から他の機器へドラッグすると線を引けます。</p>
      <button className="btn btn-danger" onClick={onRemove} style={{ marginTop: 8 }}>削除</button>
    </Section>
  );
}

function DecorationPanel({
  node, editing, onChange, onRemove,
}: { node: CloudNode | TextNode | AreaNode; editing: boolean; onChange: (p: Record<string, unknown>) => void; onRemove: () => void }) {
  const title = DECOR_TITLE[node.type];
  if (!editing) {
    return <Section title={`選択中: ${title}`}><p style={{ whiteSpace: "pre-wrap" }}>{node.data.label || "（文字なし）"}</p></Section>;
  }
  return (
    <Section title={`選択中: ${title}`}>
      <div className="form-group">
        <label className="form-label" htmlFor="decor-label">文字</label>
        <textarea id="decor-label" rows={node.type === "text" ? 3 : 2} value={node.data.label}
          onChange={(e) => onChange({ label: e.target.value })} />
      </div>
      {node.type === "text" && (
        <div className="form-group">
          <label className="form-label" htmlFor="decor-size">文字の大きさ</label>
          <select id="decor-size" value={node.data.fontSize ?? "m"} onChange={(e) => onChange({ fontSize: e.target.value as FontSize })}>
            <option value="s">小</option><option value="m">中</option><option value="l">大</option><option value="xl">特大</option>
          </select>
        </div>
      )}
      <ColorPicker label="色" value={node.data.color} onChange={(color) => onChange({ color })} />
      {node.type !== "text" && <p className="topo-muted topo-small">選択中に四隅をドラッグすると大きさを変えられます。</p>}
      <button className="btn btn-danger" onClick={onRemove} style={{ marginTop: 8 }}>削除</button>
    </Section>
  );
}

function EdgePanel({
  edge, nodes, statuses, editing, onChange, onRemove,
}: {
  edge: LinkEdge; nodes: TopoNode[]; statuses: Record<string, DeviceStatus>; editing: boolean;
  onChange: (p: Partial<NonNullable<LinkEdge["data"]>>) => void; onRemove: () => void;
}) {
  const name = (id: string) => {
    const n = nodes.find((x) => x.id === id);
    if (!n) return "?";
    if (n.type === "device") return statuses[n.data.deviceId]?.name ?? "機器";
    if (n.type === "point") return DECOR_TITLE.point;
    return n.data.label.split("\n")[0] || DECOR_TITLE[n.type];
  };
  const d = edge.data ?? {};
  const a = name(edge.source);
  const b = name(edge.target);
  if (!editing) {
    return (
      <Section title="選択中の接続線">
        <dl className="topo-kv">
          <dt>{a}</dt><dd className="mono">{d.sourcePort || "—"}</dd>
          <dt>{b}</dt><dd className="mono">{d.targetPort || "—"}</dd>
          {d.label && (<><dt>ラベル</dt><dd>{d.label}</dd></>)}
        </dl>
      </Section>
    );
  }
  return (
    <Section title="選択中の接続線">
      <div className="form-group">
        <label className="form-label" htmlFor="port-a">{a} 側のポート</label>
        <input id="port-a" className="mono" value={d.sourcePort ?? ""} maxLength={64} placeholder="例: Gi1/0/48"
          onChange={(e) => onChange({ sourcePort: e.target.value })} />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="port-b">{b} 側のポート</label>
        <input id="port-b" className="mono" value={d.targetPort ?? ""} maxLength={64} placeholder="例: ethernet1/1"
          onChange={(e) => onChange({ targetPort: e.target.value })} />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="edge-label">ラベル（任意）</label>
        <input id="edge-label" value={d.label ?? ""} maxLength={500} placeholder="例: Po1 / 10G / VLAN 10"
          onChange={(e) => onChange({ label: e.target.value })} />
      </div>
      <div className="topo-form-row">
        <div className="form-group">
          <label className="form-label" htmlFor="edge-style">線の種類</label>
          <select id="edge-style" value={d.lineStyle ?? "solid"} onChange={(e) => onChange({ lineStyle: e.target.value as LineStyle })}>
            <option value="solid">実線</option>
            <option value="dashed">破線</option>
            <option value="dotted">点線</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="edge-width">太さ</label>
          <select id="edge-width" value={d.width ?? "normal"} onChange={(e) => onChange({ width: e.target.value as LineWidth })}>
            <option value="thin">細い</option>
            <option value="normal">普通</option>
            <option value="thick">太い</option>
          </select>
        </div>
      </div>
      <div className="topo-form-row">
        <div className="form-group">
          <label className="form-label" htmlFor="edge-routing">経路</label>
          <select id="edge-routing" value={d.routing ?? "straight"} onChange={(e) => onChange({ routing: e.target.value as Routing })}>
            <option value="straight">直線</option>
            <option value="step">カギ線</option>
            <option value="curve">曲線</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="edge-arrow">矢印</label>
          <select id="edge-arrow" value={d.arrow ?? "none"} onChange={(e) => onChange({ arrow: e.target.value as Arrow })}>
            <option value="none">なし</option>
            <option value="end">{b} 側</option>
            <option value="start">{a} 側</option>
            <option value="both">両方</option>
          </select>
        </div>
      </div>
      <ColorPicker label="色" value={d.color} onChange={(color) => onChange({ color })} />
      <button className="btn btn-danger" onClick={onRemove}>線を削除</button>
    </Section>
  );
}

function MultiPanel({ count, editing, onDelete }: { count: number; editing: boolean; onDelete: () => void }) {
  return (
    <Section title="複数選択">
      <p>{count} 個を選択中</p>
      {editing && (
        <>
          <p className="topo-muted topo-small" style={{ margin: "6px 0 10px" }}>ドラッグでまとめて移動できます。</p>
          <button className="btn btn-danger" onClick={onDelete}>選択したものを削除</button>
        </>
      )}
    </Section>
  );
}

function Palette({
  view, devices, placed, onAddDevice, onAddDecoration,
}: {
  view: ViewKind; devices: DeviceItem[]; placed: Set<string>;
  onAddDevice: (id: string) => void; onAddDecoration: (k: AddKind, shape?: ShapeKind) => void;
}) {
  const [q, setQ] = useState("");
  const rest = devices
    .filter((d) => !placed.has(d.id))
    .filter((d) => !q || `${d.name} ${d.hostname}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <Section title="追加">
        <div className="topo-decor-buttons">
          <button className="btn topo-add-unmanaged" onClick={() => onAddDecoration("unmanaged")}>＋ 非管理機器</button>
          <button className="btn" onClick={() => onAddDecoration("cloud")}>雲</button>
          <button className="btn" onClick={() => onAddDecoration("text")}>テキスト</button>
          <button className="btn" onClick={() => onAddDecoration("area")}>グループ枠</button>
        </div>
      </Section>
      {view === "logical" && (
        <Section title="作図">
          <div className="topo-shape-buttons">
            {(Object.keys(SHAPE_LABELS) as ShapeKind[]).map((k) => (
              <button key={k} className="btn topo-shape-btn" onClick={() => onAddDecoration("shape", k)} title={`${SHAPE_LABELS[k]}を追加`}>
                <ShapeIcon shape={k} />{SHAPE_LABELS[k]}
              </button>
            ))}
          </div>
          <div className="topo-decor-buttons" style={{ marginTop: 6 }}>
            <button className="btn" onClick={() => onAddDecoration("segment")}>セグメント</button>
            <button className="btn" onClick={() => onAddDecoration("point")}>中継点</button>
          </div>
          <p className="topo-muted topo-small" style={{ marginTop: 6 }}>
            線は選択すると矢印・カギ線・曲線・太さを変えられます。
          </p>
        </Section>
      )}
      <Section title={`未配置の機器（${devices.length - placed.size}）`}>
        <input placeholder="名前・IPで絞り込み" value={q} onChange={(e) => setQ(e.target.value)} aria-label="未配置の機器を絞り込み" style={{ marginBottom: 8 }} />
        {rest.length === 0 ? (
          <p className="topo-muted topo-small">{devices.length ? "すべて配置済みです" : "機器が登録されていません"}</p>
        ) : (
          <ul className="topo-device-list">
            {rest.map((d) => (
              <li key={d.id}>
                <button
                  className="topo-device-item"
                  draggable
                  onDragStart={(e) => {
                    e.dataTransfer.setData("application/x-netconfig-device", d.id);
                    e.dataTransfer.effectAllowed = "move";
                  }}
                  onClick={() => onAddDevice(d.id)}
                  title="ドラッグして配置（クリックで中央に配置）"
                >
                  <span className="topo-grip" aria-hidden="true">⋮⋮</span>
                  <span className="topo-device-item-name">{d.name}</span>
                  <span className="topo-muted topo-small">{d.hostname}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </>
  );
}

function ShapeIcon({ shape }: { shape: ShapeKind }) {
  const c = { fill: "none", stroke: "currentColor", strokeWidth: 1.6 };
  return (
    <svg width="16" height="12" viewBox="0 0 16 12" aria-hidden="true">
      {shape === "ellipse" ? <ellipse cx="8" cy="6" rx="7" ry="5" {...c} />
        : shape === "diamond" ? <polygon points="8,1 15,6 8,11 1,6" {...c} />
        : <rect x="1" y="1" width="14" height="10" rx={shape === "rounded" ? 3 : 0} {...c} />}
    </svg>
  );
}
