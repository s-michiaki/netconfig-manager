import { Fragment, ReactNode, useEffect, useMemo, useState } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth";
import { findTopic, HELP_GROUPS, HELP_TOPICS, README_URL, readmeAnchor, searchText, type HelpTopic } from "../help/topics";

/** 本文の `コード` を等幅（<code>）にする。ほかの記法は使わない */
type Features = Record<string, boolean> | null | undefined; // undefined: 読み込み中、null: 読めなかった

function inline(text: string): ReactNode {
  return text.split(/(`[^`]+`)/).map((part, i) =>
    part.length > 2 && part.startsWith("`") && part.endsWith("`")
      ? <code key={i} className="mono">{part.slice(1, -1)}</code>
      : <Fragment key={i}>{part}</Fragment>,
  );
}

/** その画面を開けるか・開けない理由 */
function ScreenAccess({ topic, features }: { topic: HelpTopic; features: Features }) {
  const { can } = useAuth();
  if (!topic.path) {
    return topic.roles === "管理者" ? <p className="help-access help-access-note">この項目は管理者向けです。</p> : null;
  }
  if (topic.perm && !can(topic.perm)) {
    return <p className="help-access help-access-note">この画面は{topic.roles}が使えます。</p>;
  }
  if (topic.feature) {
    if (features === undefined) return null; // 設定を読み込むまでは何も出さない
    // 読めなかったとき（null）は無効とは言えないので、権限だけで開くリンクを出す
    if (features && !features[topic.feature]) return <p className="help-access help-access-note">この環境では無効になっています。</p>;
  }
  return (
    <p className="help-access">
      <Link className="btn btn-primary btn-sm" to={topic.path}>この画面を開く</Link>
    </p>
  );
}

/** README の案内（管理者向けの項目だけ） */
function ReadmeLinks({ topic }: { topic: HelpTopic }) {
  if (!topic.readme?.length) return null;
  return (
    <section className="help-section">
      <h3>くわしい手順（README）</h3>
      <ul className="help-readme">
        {topic.readme.map((r) => {
          const anchor = readmeAnchor(r.heading);
          return (
            <li key={r.heading}>
              <a href={anchor ? `${README_URL}#${anchor}` : README_URL} target="_blank" rel="noopener noreferrer">{r.heading}</a>
              {!anchor && <span className="topo-muted topo-small">（README を開いて、この見出しの節を探してください）</span>}
              {r.note && <span className="topo-muted topo-small"> {r.note}</span>}
            </li>
          );
        })}
      </ul>
      <p className="topo-muted topo-small">GitHub を開けない環境では、サーバーの <code className="mono">/opt/netconfig-manager/README.md</code> を参照してください。</p>
    </section>
  );
}

function Article({ topic, features }: { topic: HelpTopic; features: Features }) {
  return (
    <article className="help-article card" aria-labelledby="help-article-title">
      <p className="topo-muted topo-small">{topic.group}</p>
      <h2 id="help-article-title">{topic.title}</h2>
      <ScreenAccess topic={topic} features={features} />
      <p className="help-summary">{inline(topic.summary)}</p>
      <section className="help-section">
        <h3>基本の使い方</h3>
        <ol className="help-steps">
          {topic.steps.map((s) => (
            <li key={s.title}>
              <b>{s.title}</b>
              {s.body.map((line, i) => <p key={i}>{inline(line)}</p>)}
            </li>
          ))}
        </ol>
      </section>
      <section className="help-section">
        <h3>つまずきやすいところ・注意</h3>
        <ul className="help-tips">
          {topic.tips.map((t, i) => <li key={i}>{inline(t)}</li>)}
        </ul>
      </section>
      <ReadmeLinks topic={topic} />
    </article>
  );
}

function Intro() {
  const { me } = useAuth();
  return (
    <article className="help-article card" aria-labelledby="help-article-title">
      <h2 id="help-article-title">はじめに</h2>
      <p className="help-summary">
        各画面で「何ができるか」と「基本の使い方」を読めます。左の一覧から画面を選んでください。
        各画面の見出しの横の「?」からも、その画面のヘルプを開けます。
      </p>
      <ul className="help-tips">
        <li>探したい言葉は、左上の検索欄に入力すると絞り込めます。</li>
        {me && <li>いまのロールは「{me.role_label}」です。使えない画面の項目にも、どのロールが使えるかが書かれています。</li>}
        <li>ログイン・2 段階認証・API トークン・ロールについては、「共通」の項目を参照してください。</li>
        <li>導入・更新・サーバーの設定は、画面ではなくサーバーで行います。「導入・更新・バックアップ」から、くわしい手順（README）へ進めます。</li>
      </ul>
    </article>
  );
}

export default function HelpPage() {
  const { topicId } = useParams();
  const [query, setQuery] = useState("");
  const [features, setFeatures] = useState<Features>(undefined);
  useEffect(() => {
    api.get<{ features?: Record<string, boolean> }>("/health")
      .then((r) => setFeatures(r.data.features ?? {}))
      .catch(() => setFeatures(null));
  }, []);

  const q = query.trim().toLowerCase();
  const shown = useMemo(() => (q ? HELP_TOPICS.filter((t) => searchText(t).includes(q)) : HELP_TOPICS), [q]);
  const topic = findTopic(topicId);
  if (topicId && !topic) return <Navigate to="/help" replace />;

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">ヘルプ</span>
        <span className="topo-muted topo-small">各画面でできることと、基本の使い方</span>
      </div>
      <div className="page-body">
        <div className="help-layout">
          <nav className="help-nav" aria-label="ヘルプの項目">
            <input
              type="search" className="help-search" value={query} onChange={(e) => setQuery(e.target.value)}
              placeholder="ヘルプを検索" aria-label="ヘルプを検索"
            />
            <Link to="/help" className={`help-nav-item${!topic ? " active" : ""}`}>はじめに</Link>
            {shown.length === 0 && <p className="topo-muted topo-small help-empty" role="status">見つかりません</p>}
            {HELP_GROUPS.map((g) => {
              const items = shown.filter((t) => t.group === g);
              if (items.length === 0) return null;
              return (
                <div key={g} className="help-nav-group">
                  <p className="help-nav-head">{g}</p>
                  {items.map((t) => (
                    <Link key={t.id} to={`/help/${t.id}`} className={`help-nav-item${topic?.id === t.id ? " active" : ""}`}
                      aria-current={topic?.id === t.id ? "page" : undefined}>
                      {t.title}
                    </Link>
                  ))}
                </div>
              );
            })}
          </nav>
          {topic ? <Article topic={topic} features={features} /> : <Intro />}
        </div>
      </div>
    </div>
  );
}
