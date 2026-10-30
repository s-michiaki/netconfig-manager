/** 機器間の接続線。ノードの中心どうしを結ぶ直線を、それぞれのノードの縁で切って描く */
import { memo } from "react";
import {
  BaseEdge, EdgeLabelRenderer, useInternalNode, type EdgeProps, type InternalNode,
} from "@xyflow/react";
import type { LinkEdge } from "./model";

type Pt = { x: number; y: number };

function center(n: InternalNode): Pt {
  const p = n.internals.positionAbsolute;
  return { x: p.x + (n.measured.width ?? 0) / 2, y: p.y + (n.measured.height ?? 0) / 2 };
}

/** from の中心から to の方向へ伸ばした線と、from の外枠（矩形）との交点 */
function borderPoint(from: InternalNode, toward: Pt, pad = 2): Pt {
  const c = center(from);
  const hw = (from.measured.width ?? 0) / 2 + pad;
  const hh = (from.measured.height ?? 0) / 2 + pad;
  const dx = toward.x - c.x;
  const dy = toward.y - c.y;
  if (dx === 0 && dy === 0) return c;
  const scale = 1 / Math.max(Math.abs(dx) / hw, Math.abs(dy) / hh);
  return { x: c.x + dx * scale, y: c.y + dy * scale };
}

export const LinkEdgeView = memo(function LinkEdgeView({ id, source, target, data, selected }: EdgeProps<LinkEdge>) {
  const s = useInternalNode(source);
  const t = useInternalNode(target);
  if (!s || !t) return null;

  const sc = center(s);
  const tc = center(t);
  const sp = borderPoint(s, tc);
  const tp = borderPoint(t, sc);
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
  const p1 = { x: sp.x + ox, y: sp.y + oy };
  const p2 = { x: tp.x + ox, y: tp.y + oy };
  const path = `M ${p1.x},${p1.y} L ${p2.x},${p2.y}`;

  const color = selected ? "#4f8ef7" : data?.color ?? "#5b6390";
  const at = (r: number) => ({ x: p1.x + (p2.x - p1.x) * r, y: p1.y + (p2.y - p1.y) * r });
  const len = Math.hypot(p2.x - p1.x, p2.y - p1.y);
  // 線が短いときはポート名を端に寄せすぎない
  const r = len > 0 ? Math.min(0.35, 34 / len) : 0.2;
  const mid = at(0.5);
  const sl = at(r);
  const tl = at(1 - r);

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        interactionWidth={16}
        style={{
          stroke: color, strokeWidth: selected ? 3 : 2,
          strokeDasharray: data?.lineStyle === "dashed" ? "7 5" : undefined,
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
