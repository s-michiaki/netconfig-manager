import { Link } from "react-router-dom";

/**
 * 画面の見出しの横に置く小さな「?」。その画面のヘルプ（/help/<項目>）を開く。
 * 「?」は CSS で描く（見出しの文字を変えないため）。topic はヘルプの項目の id（画面のパスの先頭の語）
 */
export default function HelpLink({ topic }: { topic: string }) {
  return <Link to={`/help/${topic}`} className="help-link" aria-label="この画面のヘルプ" title="この画面のヘルプ" />;
}
