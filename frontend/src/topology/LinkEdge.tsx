/** 接続線
 * - 直線: ノードの中心どうしを結ぶ線を、それぞれのノードの縁で切って描く
 * - カギ線: 向かい合う辺の中央から、水平・垂直の線で結ぶ
 * - 曲線: 直線を少したわませた曲線
 * セグメント（サブネット等の線）につないだ場合は、セグメント上に垂直に落ちる位置を端点にする
 */
import { memo } from "react";
import {
  BaseEdge, EdgeLabelRenderer, useInternalNode, type EdgeProps, type InternalNode,
} from "@xyflow/react";
import { DEFAULT_EDGE_COLOR, type LinkEdge } from "./model";

type Pt = { x: number; y: number };
type Dir = "h" | "v";

function box(n: InternalNode) {
  const p = n.internals.positionAbsolute;
  const w = n.measured.width ?? 0;
  const h = n.measured.height ?? 0;
  return { x: p.x, y: p.y, w, h, cx: p.x + w / 2, cy: p.y + h / 2 };
}

const isSegment = (n: InternalNode) => n.type === "segment";
const isPoint = (n: InternalNode) => n.type === "point";
const segVertical = (n: InternalNode) => (n.measured.height ?? 0) > (n.measured.width ?? 0);
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

/** 相手から見たこのノードの基準点（セグメントは線上の最寄り点、それ以外は中心） */
function refPoint(n: InternalNode, other: Pt): Pt {
  const b = box(n);
  if (!isSegment(n)) return { x: b.cx, y: b.cy };
  return segVertical(n)
    ? { x: b.cx, y: clamp(other.y, b.y + 4, b.y + b.h - 4) }
    : { x: clamp(other.x, b.x + 4, b.x + b.w - 4), y: b.cy };
}

/** n の中心から toward の方向へ伸ばした線と、n の外枠との交点 */
function borderPoint(n: InternalNode, toward: Pt, pad = 2): Pt {
  const b = box(n);
  const hw = b.w / 2 + pad;
  const hh = b.h / 2 + pad;
  const dx = toward.x - b.cx;
  const dy = toward.y - b.cy;
  if (dx === 0 && dy === 0) return { x: b.cx, y: b.cy };
  const s = 1 / Math.max(Math.abs(dx) / hw, Math.abs(dy) / hh);
  return { x: b.cx + dx * s, y: b.cy + dy * s };
}

/** 直線・曲線の端点 */
function straightEnd(n: InternalNode, otherRef: Pt): Pt {
  if (isSegment(n)) return refPoint(n, otherRef);
  if (isPoint(n)) return { x: box(n).cx, y: box(n).cy };
  return borderPoint(n, otherRef);
}

/** カギ線の端点と、そこから出ていく向き */
function stepEnd(n: InternalNode, otherRef: Pt): { p: Pt; dir: Dir } {
  const b = box(n);
  if (isSegment(n)) return { p: refPoint(n, otherRef), dir: segVertical(n) ? "h" : "v" };
  const dx = otherRef.x - b.cx;
  const dy = otherRef.y - b.cy;
  if (isPoint(n)) return { p: { x: b.cx, y: b.cy }, dir: Math.abs(dx) >= Math.abs(dy) ? "h" : "v" };
  if (Math.abs(dx) / (b.w || 1) >= Math.abs(dy) / (b.h || 1)) {
    return { p: { x: dx >= 0 ? b.x + b.w + 2 : b.x - 2, y: b.cy }, dir: "h" };
  }
  return { p: { x: b.cx, y: dy >= 0 ? b.y + b.h + 2 : b.y - 2 }, dir: "v" };
}

function stepPoints(a: { p: Pt; dir: Dir }, b: { p: Pt; dir: Dir }): Pt[] {
  const p1 = a.p;
  const p2 = b.p;
  if (a.dir === "h" && b.dir === "h") {
    const mx = (p1.x + p2.x) / 2;
    return [p1, { x: mx, y: p1.y }, { x: mx, y: p2.y }, p2];
  }
  if (a.dir === "v" && b.dir === "v") {
    const my = (p1.y + p2.y) / 2;
    return [p1, { x: p1.x, y: my }, { x: p2.x, y: my }, p2];
  }
  // 向きが異なる場合は1回だけ曲げる
  return a.dir === "h" ? [p1, { x: p2.x, y: p1.y }, p2] : [p1, { x: p1.x, y: p2.y }, p2];
}

/** 折れ線上で、始点から距離 d の位置 */
function along(pts: Pt[], d: number): Pt {
  for (let i = 1; i < pts.length; i++) {
    const seg = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
    if (d <= seg || i === pts.length - 1) {
      const r = seg ? Math.min(1, d / seg) : 0;
      return { x: pts[i - 1].x + (pts[i].x - pts[i - 1].x) * r, y: pts[i - 1].y + (pts[i].y - pts[i - 1].y) * r };
    }
    d -= seg;
  }
  return pts[pts.length - 1];
}
const polyLength = (pts: Pt[]) =>
  pts.slice(1).reduce((s, p, i) => s + Math.hypot(p.x - pts[i].x, p.y - pts[i].y), 0);

const WIDTH = { thin: 1.2, normal: 2, thick: 3.5 } as const;
const DASH = { solid: undefined, dashed: "7 5", dotted: "1.5 5" } as const;

export const LinkEdgeView = memo(function LinkEdgeView({
  id, source, target, data, selected, markerStart, markerEnd,
}: EdgeProps<LinkEdge>) {
  const s = useInternalNode(source);
  const t = useInternalNode(target);
  if (!s || !t) return null;

  const routing = data?.routing ?? "straight";
  const sc = { x: box(s).cx, y: box(s).cy };
  const tc = { x: box(t).cx, y: box(t).cy };
  // セグメント側の基準点は、相手の中心からの垂線の足
  const sRef = refPoint(s, tc);
  const tRef = refPoint(t, sc);

  // 同じ2ノード間に複数本あるときは、線に垂直な方向へ平行にずらす
  // （線の向きに依らず同じ側へずらすため、ノードID順で向きを揃える）
  let ox = 0;
  let oy = 0;
  const count = data?.parallelCount ?? 1;
  if (count > 1) {
    const [a, b] = source < target ? [sc, tc] : [tc, sc];
    const d = Math.hypot(b.x - a.x, b.y - a.y) || 1;
    const off = ((data?.parallelIndex ?? 0) - (count - 1) / 2) * 14;
    ox = (-(b.y - a.y) / d) * off;
    oy = ((b.x - a.x) / d) * off;
  }
  const shift = (p: Pt) => ({ x: p.x + ox, y: p.y + oy });

  let path: string;
  let pts: Pt[]; // ラベル位置の計算用
  if (routing === "step") {
    pts = stepPoints(stepEnd(s, tRef), stepEnd(t, sRef)).map(shift);
    path = `M ${pts.map((p) => `${p.x},${p.y}`).join(" L ")}`;
  } else {
    const p1 = shift(straightEnd(s, tRef));
    const p2 = shift(straightEnd(t, sRef));
    if (routing === "curve") {
      const len = Math.hypot(p2.x - p1.x, p2.y - p1.y) || 1;
      const k = 0.22 * len;
      const c = { x: (p1.x + p2.x) / 2 - ((p2.y - p1.y) / len) * k, y: (p1.y + p2.y) / 2 + ((p2.x - p1.x) / len) * k };
      path = `M ${p1.x},${p1.y} Q ${c.x},${c.y} ${p2.x},${p2.y}`;
      // 2次ベジェ曲線を折れ線で近似してラベル位置に使う
      pts = Array.from({ length: 17 }, (_, i) => {
        const u = i / 16;
        return {
          x: (1 - u) ** 2 * p1.x + 2 * (1 - u) * u * c.x + u ** 2 * p2.x,
          y: (1 - u) ** 2 * p1.y + 2 * (1 - u) * u * c.y + u ** 2 * p2.y,
        };
      });
    } else {
      pts = [p1, p2];
      path = `M ${p1.x},${p1.y} L ${p2.x},${p2.y}`;
    }
  }

  const color = selected ? "#4f8ef7" : data?.color ?? DEFAULT_EDGE_COLOR;
  const len = polyLength(pts);
  // 線が短いときはポート名を端に寄せすぎない
  const end = Math.min(len * 0.35, 34);
  const mid = along(pts, len / 2);
  const sl = along(pts, end);
  const tl = along(pts, len - end);
  const style = data?.lineStyle ?? "solid";

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerStart={markerStart}
        markerEnd={markerEnd}
        interactionWidth={16}
        style={{
          stroke: color,
          strokeWidth: WIDTH[data?.width ?? "normal"] + (selected ? 1 : 0),
          strokeDasharray: DASH[style],
          strokeLinecap: style === "dotted" ? "round" : undefined,
          fill: "none",
        }}
      />
      <EdgeLabelRenderer>
        {data?.sourcePort && (
          <div className="topo-port" style={{ transform: `translate(-50%,-50%) translate(${sl.x}px,${sl.y}px)` }}>
            {data.sourcePort}
          </div>
        )}
        {data?.targetPort && (
          <div className="topo-port" style={{ transform: `translate(-50%,-50%) translate(${tl.x}px,${tl.y}px)` }}>
            {data.targetPort}
          </div>
        )}
        {data?.label && (
          <div
            className={`topo-edge-label${selected ? " selected" : ""}`}
            style={{ transform: `translate(-50%,-50%) translate(${mid.x}px,${mid.y}px)`, color: data.color ?? undefined }}
          >
            {data.label}
          </div>
        )}
      </EdgeLabelRenderer>
    </>
  );
});

export const edgeTypes = { link: LinkEdgeView };
