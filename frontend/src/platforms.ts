import { useEffect, useMemo, useState } from "react";
import { api } from "./api/client";

/** 対応プラットフォーム（backend/app/services/config_service.py の PLATFORMS が元。/api/devices/platforms で取得） */
export interface PlatformInfo {
  id: string;
  label: string;
  vendor: string;
  icon: string;
  supports_enable: boolean;
  note: string | null;
}

let cached: PlatformInfo[] | null = null;
let loading: Promise<PlatformInfo[]> | null = null;

function load(): Promise<PlatformInfo[]> {
  if (cached) return Promise.resolve(cached);
  if (!loading) {
    loading = api
      .get<PlatformInfo[]>("/devices/platforms")
      .then((r) => (cached = r.data))
      .catch((e) => {
        loading = null; // 次の画面表示で再取得する
        throw e;
      });
  }
  return loading;
}

/** メーカーごとにまとめる（並びは backend の定義順） */
export function groupByVendor(list: PlatformInfo[]): [string, PlatformInfo[]][] {
  const groups = new Map<string, PlatformInfo[]>();
  for (const p of list) groups.set(p.vendor, [...(groups.get(p.vendor) ?? []), p]);
  return [...groups.entries()];
}

export function usePlatforms() {
  const [platforms, setPlatforms] = useState<PlatformInfo[]>(cached ?? []);
  useEffect(() => {
    let alive = true;
    load().then((list) => alive && setPlatforms(list)).catch(() => undefined);
    return () => { alive = false; };
  }, []);
  return useMemo(() => {
    const byId: Record<string, PlatformInfo> = Object.fromEntries(platforms.map((p) => [p.id, p]));
    return {
      platforms,
      byId,
      /** 表示名（未対応・読み込み前は ID のまま） */
      label: (id: string) => byId[id]?.label ?? id,
      groups: groupByVendor(platforms),
    };
  }, [platforms]);
}
