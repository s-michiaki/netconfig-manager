import { adminTopics } from "./content/admin";
import { commonTopics } from "./content/common";
import { configTopics } from "./content/config";
import { dashboardTopics } from "./content/dashboard";
import { devicesTopics } from "./content/devices";
import { monitorTopics } from "./content/monitor";
import type { HelpTopic } from "./types";

export type { HelpRoles, HelpTopic } from "./types";

/** 大項目（左ペインのメニューと同じ並び。最後に共通の項目） */
export const HELP_GROUPS = ["ダッシュボード", "機器", "コンフィグ", "監視", "管理", "共通"] as const;

/** ヘルプの全項目。画面を足したら、content/ の該当の大項目に項目を足す（テストが漏れを検出する） */
export const HELP_TOPICS: HelpTopic[] = [
  ...dashboardTopics,
  ...devicesTopics,
  ...configTopics,
  ...monitorTopics,
  ...adminTopics,
  ...commonTopics,
];

export function findTopic(id: string | undefined): HelpTopic | undefined {
  return id ? HELP_TOPICS.find((t) => t.id === id) : undefined;
}

/** README（GitHub）。GitHub を開けない環境では、サーバーの /opt/netconfig-manager/README.md を参照する */
export const README_URL = "https://github.com/s-michiaki/netconfig-manager/blob/master/README.md";

/**
 * README の見出しへのリンク用のアンカー（GitHub の規則: 小文字にして、空白をハイフンにする）。
 * 記号（括弧・スラッシュ・全角記号など）を含む見出しは規則に自信が持てないので null（README の先頭へのリンクにする）
 */
export function readmeAnchor(heading: string): string | null {
  if (!/^[\p{L}\p{N}\p{M}_ -]+$/u.test(heading)) return null;
  return heading.trim().toLowerCase().replace(/ /g, "-");
}

/** 検索の対象にする文字（title・summary・steps・tips） */
export function searchText(t: HelpTopic): string {
  return [t.title, t.summary, ...t.steps.flatMap((s) => [s.title, ...s.body]), ...t.tips].join("\n").toLowerCase();
}
