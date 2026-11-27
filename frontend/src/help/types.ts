import type { Perm } from "../auth";

/** その画面を使えるロール（backend/app/core/permissions.py の ROLE_PERMISSIONS と合わせる。テストが確かめる） */
export type HelpRoles = "管理者" | "オペレーター以上" | "すべてのロール";

/** ヘルプの 1 項目（画面 1 枚ぶん）。本文の `…` は等幅で表示する */
export type HelpTopic = {
  id: string; // URL に使う。画面の項目は、パスの先頭の語（/devices なら "devices"）
  title: string; // 左ペインのメニューの表記と同じ
  group: string; // 大項目（HELP_GROUPS のどれか）
  path?: string; // 対応する画面のパス（共通の項目は無し）
  perm?: Perm; // その画面に要る権限（App.tsx の Route と同じ）
  roles?: HelpRoles; // perm を持つ最も下のロール
  feature?: string; // 機能の設定で無効になりうるもの（App.tsx の NavItem.feature と同じ値）
  summary: string; // 何ができるか（1〜3 文）
  steps: { title: string; body: string[] }[]; // 基本の使い方（操作の順）
  tips: string[]; // よくあるつまずき・注意
  readme?: { heading: string; note?: string }[]; // README の該当の見出し（管理者向けの案内）
};
