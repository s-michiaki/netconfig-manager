"""コンフィグ履歴を外部の Git サーバー（GitLab / Gitea など）へ push する

機器ごとのリポジトリ（GIT_REPO_PATH/<機器ID>/）はそのまま使い、別に「書き出し用のリポジトリ」を 1 つ持つ。
書き出し用のリポジトリは人が読みやすい形にする:

    README.md                  機器の一覧（名前・ホスト・機種・グループ・最後に変わった日時）
    <グループ名>/<機器名>.txt   最後に収集したコンフィグ（グループなしは「未分類」）

同期（sync）では、全機器の最新コンフィグを書き出し用のリポジトリへコピーし、変わっていればコミットして push する。
- 収集でコンフィグが変わったら、GIT_EXPORT_DELAY_SEC 秒後に 1 回同期する（一括収集で何台変わっても 1 コミット）
- 送り損ねたとき（相手が止まっていた等）に備えて、1 時間ごとにも同期する（変更が無く push 済みなら何もしない）
- 削除・改名した機器のファイルは消す。コミットのメッセージに変わった機器を書く
- 認証は HTTPS（GIT_EXPORT_USERNAME / GIT_EXPORT_TOKEN。GIT_ASKPASS で渡し、URL や .git/config に残さない）か
  SSH（GIT_EXPORT_SSH_KEY の秘密鍵。初回に相手のホスト鍵を記録し、以後は変わったら拒否する）
- 結果は Redis に残し、システム状態に表示する。失敗はシステムの異常として通知する（services/system.py）
- プロキシ（core/outbound.py の OUTBOUND_PROXY）: https:// の宛先が outbound.use_proxy に当たるときだけ、git のプロセスの
  環境変数（https_proxy など）で渡す。コマンドラインの引数・.git/config には書かない（プロセス一覧・ファイルに認証情報を
  残さない。#14 と同じ考え）。当たらない宛先・SSH（ssh://・git@host:path）・ローカルのパスでは、プロキシの環境変数を明示的に
  空にする（コンテナの環境に何が入っていても使わない）。平文（http://）の宛先をプロキシ経由では送らない（外へは HTTPS だけ）
- 追加の CA: OUTBOUND_CA_FILE があれば、https の宛先で
    GIT_EXPORT_CA_FILE なし → OS の信頼（束）＋ OUTBOUND_CA_FILE を一時ファイルに束ねて GIT_SSL_CAINFO で渡す
    GIT_EXPORT_CA_FILE あり → GIT_EXPORT_CA_FILE ＋ OUTBOUND_CA_FILE を束ねて http.sslCAInfo に渡す
                             （OS の信頼は今までどおり使わない）
  束ねたファイルは push の一時ディレクトリに作り、終わったら消す
- git の失敗の文（stderr）は、プロキシの URL・認証情報を outbound.scrub で伏せてから記録する
"""
import json
import logging
import os
import re
import shlex
import stat
import tempfile
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import git

from app.core import outbound
from app.core.config import settings
from app.core.timeutil import utcnow
from app.services.config_service import CONFIG_FILENAME, repo_path

logger = logging.getLogger(__name__)

STATE_KEY = "netconfig:git-export:state"  # 最後の結果（JSON）
PENDING_KEY = "netconfig:git-export:pending"  # 同期を予約済みの印（同じ時間帯の収集をまとめる）
LOCK_KEY = "netconfig:git-export:lock"
UNGROUPED = "未分類"
_UNSAFE = re.compile(r'[\x00-\x1f\x7f/\\:*?"<>|]')


@dataclass
class DeviceFile:
    id: str
    name: str
    hostname: str
    platform: str
    group: str | None


def enabled() -> bool:
    return bool(settings.GIT_EXPORT_URL.strip())


def export_path() -> Path:
    return Path(settings.GIT_EXPORT_PATH or os.path.join(settings.GIT_REPO_PATH, "_export"))


def safe_name(name: str) -> str:
    """ファイル名・ディレクトリ名に使えない文字を「_」に置き換える（先頭の「.」も避ける）"""
    s = _UNSAFE.sub("_", name).strip().lstrip(".") or "_"
    return s[:120]


def mask_url(url: str) -> str:
    """URL に書かれた認証情報（https://user:pass@host）を伏せる（画面・ログ用）"""
    return re.sub(r"(https?://)[^/@\s]+@", r"\1***@", url)


def split_url(url: str) -> tuple[str, str, str]:
    """（認証情報を除いた URL, ユーザー名, パスワード）。HTTPS の URL に書かれた user:pass@ を取り出す（#14）

    取り出した値は push のときだけ環境変数で git に渡し、.git/config（バックアップにも入る）には書かない。
    SSH の URL（git@host:path）の「git@」は認証情報ではないので、そのまま
    """
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or "@" not in p.netloc:
        return url, "", ""
    host = p.netloc.rsplit("@", 1)[1]
    clean = urllib.parse.urlunsplit((p.scheme, host, p.path, p.query, p.fragment))
    return clean, urllib.parse.unquote(p.username or ""), urllib.parse.unquote(p.password or "")


def url_has_credentials(url: str) -> bool:
    _, user, password = split_url(url.strip())
    return bool(user or password)


def _layout(devices: list[DeviceFile]) -> dict[str, DeviceFile]:
    """相対パス → 機器。同じグループに同じ名前（安全な名前に直した結果）があれば ID の先頭を付けて分ける"""
    out: dict[str, DeviceFile] = {}
    for d in sorted(devices, key=lambda x: (x.group or "", x.name, x.id)):
        base = f"{safe_name(d.group or UNGROUPED)}/{safe_name(d.name)}"
        path = f"{base}.txt"
        if path.lower() in {p.lower() for p in out}:
            path = f"{base}_{d.id[:8]}.txt"
        out[path] = d
    return out


def _readme(layout: dict[str, DeviceFile], changed_at: dict[str, str]) -> str:
    lines = [
        "# ネットワーク機器のコンフィグ",
        "",
        "NetConfig Manager が収集した最新のコンフィグです（自動で更新されます。ここを直接編集しないでください）。",
        "変更の履歴はこのリポジトリのコミットで確認できます。",
        "",
        "| 機器 | ホスト | 機種 | グループ | 最後に変わった日時 |",
        "|---|---|---|---|---|",
    ]
    for path, d in layout.items():
        name = d.name.replace("|", "\\|")
        lines.append(f"| [{name}]({path.replace(' ', '%20')}) | {d.hostname} | {d.platform} | "
                     f"{(d.group or UNGROUPED).replace('|', chr(92) + '|')} | {changed_at.get(d.id, '')} |")
    return "\n".join(lines) + "\n"


def _device_repo_info(device_id: str) -> tuple[str | None, str]:
    """機器のリポジトリの最新コンフィグと、最後にコミットした日時（TIMEZONE の表記）"""
    try:
        repo = git.Repo(repo_path(device_id))
        commit = repo.head.commit
        text = (commit.tree / CONFIG_FILENAME).data_stream.read().decode("utf-8", errors="replace")
    except (ValueError, KeyError, git.InvalidGitRepositoryError, git.NoSuchPathError, git.GitCommandError):
        return None, ""
    at = datetime.fromtimestamp(commit.committed_date, tz=UTC).astimezone(ZoneInfo(settings.TIMEZONE))
    return text, at.strftime("%Y/%m/%d %H:%M")


def _open_export_repo() -> git.Repo:
    path = export_path()
    path.mkdir(parents=True, exist_ok=True)
    if (path / ".git").exists():
        repo = git.Repo(path)
    else:
        repo = git.Repo.init(path, initial_branch=settings.GIT_EXPORT_BRANCH)
    with repo.config_writer() as cw:
        name, email = _author()
        cw.set_value("user", "name", name)
        cw.set_value("user", "email", email)
    return repo


def _author() -> tuple[str, str]:
    m = re.match(r"^\s*(.*?)\s*<([^>]+)>\s*$", settings.GIT_EXPORT_AUTHOR)
    return (m.group(1) or "NetConfig Manager", m.group(2)) if m else ("NetConfig Manager", "netconfig@system.local")


def update_tree(repo: git.Repo, devices: list[DeviceFile]) -> tuple[bool, list[str]]:
    """書き出し用のリポジトリの中身を最新にしてコミットする。戻り値は (コミットしたか, 変わった機器名)"""
    root = Path(repo.working_tree_dir)
    layout = _layout(devices)
    changed_at: dict[str, str] = {}
    wanted: dict[str, str] = {}
    for path, d in layout.items():
        text, at = _device_repo_info(d.id)
        if text is None:
            continue  # 未収集の機器は書き出さない
        wanted[path] = text
        changed_at[d.id] = at
    wanted["README.md"] = _readme({p: d for p, d in layout.items() if p in wanted}, changed_at)

    # 要らなくなったファイル（削除・改名・グループの変更）を消す
    existing = [p for p in repo.git.ls_files("-z").split("\0") if p]  # -z: 日本語のパスを引用符で囲ませない
    removed = [p for p in existing if p not in wanted]
    if removed:
        repo.index.remove(removed, working_tree=True)
    names = []
    for path, text in wanted.items():
        f = root / path
        old = f.read_text(encoding="utf-8") if f.exists() else None
        if old == text:
            continue
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
        repo.index.add([path])
        if path != "README.md":
            names.append(layout[path].name)
    names += [Path(p).stem for p in removed if p != "README.md" and p.endswith(".txt")]
    # 空になったディレクトリを片付ける
    for d in sorted(root.rglob("*"), reverse=True):
        if d.is_dir() and ".git" not in d.parts and not any(d.iterdir()):
            d.rmdir()
    has_head = repo.head.is_valid()
    if has_head and not repo.index.diff("HEAD"):
        return False, []
    if not has_head and not wanted:
        return False, []
    shown = "、".join(sorted(set(names))[:20]) + (f" ほか {len(set(names)) - 20} 台" if len(set(names)) > 20 else "")
    msg = f"コンフィグの更新: {shown}" if names else "機器の一覧を更新"
    if removed:
        msg += f"（削除 {len([p for p in removed if p.endswith('.txt')])} 件）"
    name, email = _author()
    actor = git.Actor(name, email)
    repo.index.commit(msg, author=actor, committer=actor)
    return True, sorted(set(names))


def _askpass_script(tmp: str) -> str:
    """HTTPS のユーザー名・トークンを環境変数から返すスクリプト（URL・.git/config に認証情報を書かないため）

    答えるのは、宛先の Git サーバー（NCM_GIT_SCHEME://[ユーザー@]NCM_GIT_HOST）についての問いだけ。
    プロキシの認証の問い（Password for 'http://user@proxy…'）などには何も返さずに失敗する
    （GIT_EXPORT_TOKEN をプロキシのパスワードとして送らないため）。ホストは環境変数で渡し、スクリプトには埋め込まない
    """
    p = os.path.join(tmp, "askpass.sh")
    with open(p, "w", encoding="utf-8") as f:
        f.write(
            '#!/bin/sh\n'
            's="$NCM_GIT_SCHEME"; h="$NCM_GIT_HOST"\n'
            '[ -n "$s" ] && [ -n "$h" ] || exit 1\n'
            'case "$1" in\n'
            '  *"\'$s://$h\'"*|*"\'$s://$h/"*|*"\'$s://"*"@$h\'"*|*"\'$s://"*"@$h/"*) ;;\n'
            '  *) exit 1 ;;\n'
            'esac\n'
            'case "$1" in\n'
            '  Username*) printf "%s" "$NCM_GIT_USERNAME" ;;\n'
            '  *) printf "%s" "$NCM_GIT_TOKEN" ;;\n'
            'esac\n')
    os.chmod(p, stat.S_IRWXU)
    return p


_PROXY_VARS = ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY")
# OS の信頼（CA の束）の場所。python の既定（SSL_CERT_FILE を含む）→ Debian（backend のイメージ）→ RHEL 系
_OS_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem")


def _https_host(url: str) -> tuple[str, str]:
    """（scheme, ホスト）。http(s) の URL でなければ（SSH・ローカルのパス）scheme は空"""
    p = urllib.parse.urlsplit(url)
    if p.scheme in ("http", "https"):
        return p.scheme, p.hostname or ""
    return "", ""


def proxy_env(url: str) -> dict[str, str]:
    """git のプロセスに渡すプロキシの環境変数。使わないときも、すべて空にして返す（コンテナの環境の値を使わない）"""
    env = dict.fromkeys(_PROXY_VARS, "")
    scheme, host = _https_host(url)
    if not scheme:
        return env  # SSH・ローカルのパスは HTTP のプロキシを通せない（直接）
    try:
        use = outbound.use_proxy(host)
    except outbound.ProxyError as e:
        raise RuntimeError(e.message) from None
    if not use:
        return env
    if scheme == "http":
        raise RuntimeError("平文（http://）の Git サーバーへはプロキシ経由で接続しません（https:// の URL にするか、"
                           "OUTBOUND_NO_PROXY に入れてください）")
    value = settings.OUTBOUND_PROXY.strip()  # 認証情報は URL エンコードのまま（git・curl がデコードする）
    env.update(https_proxy=value, HTTPS_PROXY=value)
    return env


def _os_bundle() -> str | None:
    import ssl

    paths = ssl.get_default_verify_paths()
    for p in (paths.cafile, paths.openssl_cafile, *_OS_BUNDLES):
        if p and os.path.isfile(p):
            return p
    return None


def _ca_bundle(url: str, tmp: str) -> tuple[dict[str, str], list[str]]:
    """（環境変数, git -c のオプション）。追加の CA（OUTBOUND_CA_FILE）を束ねる。https の宛先のときだけ"""
    env: dict[str, str] = {}
    opts: list[str] = []
    extra = outbound.ca_path()
    if _https_host(url)[0] != "https" or not extra:
        if settings.GIT_EXPORT_CA_FILE:
            opts += ["-c", f"http.sslCAInfo={settings.GIT_EXPORT_CA_FILE}"]
        return env, opts
    base = settings.GIT_EXPORT_CA_FILE or _os_bundle()
    bundle = os.path.join(tmp, "ca-bundle.pem")
    with open(bundle, "wb") as out:
        for src in (base, extra):
            if not src:
                continue
            with open(src, "rb") as f:
                data = f.read()
            out.write(data if data.endswith(b"\n") else data + b"\n")
    if settings.GIT_EXPORT_CA_FILE:
        opts += ["-c", f"http.sslCAInfo={bundle}"]  # 今までどおり GIT_EXPORT_CA_FILE を使い、追加の CA を足す
    else:
        env["GIT_SSL_CAINFO"] = bundle
    return env, opts


def push(repo: git.Repo) -> str:
    """origin（GIT_EXPORT_URL）の GIT_EXPORT_BRANCH へ push する。push したコミットを返す"""
    # URL に認証情報が書かれていても、.git/config には除いた URL を保存する（以前の版で保存した分もここで消える）
    url, url_user, url_pass = split_url(settings.GIT_EXPORT_URL.strip())
    if "origin" in [r.name for r in repo.remotes]:
        if repo.remotes.origin.url != url:
            repo.remotes.origin.set_url(url)
    else:
        repo.create_remote("origin", url)
    branch = settings.GIT_EXPORT_BRANCH
    env = {"GIT_TERMINAL_PROMPT": "0"}
    opts: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        dest = urllib.parse.urlsplit(url)  # askpass が答えてよい宛先（プロキシの問いには答えない）
        env.update(NCM_GIT_SCHEME=dest.scheme, NCM_GIT_HOST=dest.netloc.rsplit("@", 1)[-1])
        if settings.GIT_EXPORT_TOKEN:
            env.update(GIT_ASKPASS=_askpass_script(tmp), NCM_GIT_USERNAME=settings.GIT_EXPORT_USERNAME or "oauth2",
                       NCM_GIT_TOKEN=settings.GIT_EXPORT_TOKEN)
        elif url_user or url_pass:  # URL に書かれた認証情報（非推奨。システム状態で注意を出す）
            env.update(GIT_ASKPASS=_askpass_script(tmp), NCM_GIT_USERNAME=url_user or "oauth2",
                       NCM_GIT_TOKEN=url_pass)
        if settings.GIT_EXPORT_SSH_KEY:
            known = settings.GIT_EXPORT_KNOWN_HOSTS
            Path(known).parent.mkdir(parents=True, exist_ok=True)
            env["GIT_SSH_COMMAND"] = " ".join([
                "ssh", "-i", shlex.quote(settings.GIT_EXPORT_SSH_KEY), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={shlex.quote(known)}",
            ])
        env.update(proxy_env(url))
        ca_env, ca_opts = _ca_bundle(url, tmp)
        env.update(ca_env)
        opts += ca_opts
        g = git.Git(repo.working_tree_dir)
        g.update_environment(**env)
        try:
            g.execute(["git", *opts, "push", "--porcelain", "origin", f"HEAD:refs/heads/{branch}"],
                      kill_after_timeout=settings.GIT_EXPORT_TIMEOUT)
        except git.GitCommandError as e:
            raise RuntimeError(_push_error(e)) from None
    return repo.head.commit.hexsha


def _push_error(e: git.GitCommandError) -> str:
    """push の失敗を短い日本語の説明にする（認証情報は含めない）"""
    err = outbound.scrub(mask_url(str(e.stderr or e).strip()))
    low = err.lower()
    if "rejected" in low or "non-fast-forward" in low or "fetch first" in low:
        hint = ("相手のブランチに、こちらに無いコミットがあります（相手側で直接変更された可能性）。"
                "相手のブランチを確認してください")
    elif "407" in low or "proxy authentication" in low:
        hint = "プロキシの認証に失敗しました（OUTBOUND_PROXY のユーザー名・パスワードを確認してください）"
    elif "authentication" in low or "could not read username" in low or "403" in low or "401" in low:
        hint = "認証に失敗しました（GIT_EXPORT_USERNAME / GIT_EXPORT_TOKEN、またはトークンの権限を確認してください）"
    elif "permission denied (publickey" in low:
        hint = "SSH の鍵で認証できません（GIT_EXPORT_SSH_KEY と、相手に登録した公開鍵を確認してください）"
    elif "host key verification failed" in low or "remote host identification has changed" in low:
        hint = f"相手のホスト鍵が以前と違います（{settings.GIT_EXPORT_KNOWN_HOSTS} を確認してください）"
    elif "certificate" in low or "ssl" in low:
        hint = ("HTTPS の証明書を確認できません（社内の CA なら GIT_EXPORT_CA_FILE、HTTPS を検査するプロキシなら"
                " OUTBOUND_CA_FILE を設定してください）")
    elif "could not resolve" in low or "connection refused" in low or "timed out" in low or "unable to access" in low:
        hint = "Git サーバーに接続できません（URL・ネットワークを確認してください）"
    elif "not found" in low or "does not appear to be a git repository" in low:
        hint = "リポジトリが見つかりません（URL と、相手にリポジトリを作ってあるかを確認してください）"
    else:
        hint = "push に失敗しました"
    # git の出力のうち、原因の分かる最初の行（fatal: / error: / ! [rejected]）を添える
    m = re.search(r"(fatal: [^\n]+|error: [^\n]+|! \[rejected\][^\n]*)", err)
    return f"{hint}（{m.group(1).strip().rstrip(chr(39))[:300]}）" if m else hint


def load_state(r) -> dict:
    try:
        raw = r.get(STATE_KEY)
        return json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        return {}


def sync(r, devices: list[DeviceFile], now: datetime | None = None) -> dict:
    """書き出し用のリポジトリを更新して push する。結果を Redis に残して返す"""
    now = now or utcnow()
    state = load_state(r)
    result: dict = {"at": now.isoformat(), "url": mask_url(settings.GIT_EXPORT_URL.strip()),
                    "branch": settings.GIT_EXPORT_BRANCH}
    try:
        repo = _open_export_repo()
        committed, names = update_tree(repo, devices)
        result.update(committed=committed, devices=names)
        head = repo.head.commit.hexsha if repo.head.is_valid() else None
        if head is None:
            result.update(ok=True, pushed=None, message="書き出すコンフィグがありません",
                          last_success=state.get("last_success"))
        elif head == state.get("pushed") and not committed:
            result.update(ok=True, pushed=head, message="変更はありません", skipped=True,
                          last_success=state.get("last_success") or now.isoformat())
        else:
            pushed = push(repo)
            result.update(ok=True, pushed=pushed, last_success=now.isoformat(),
                          message=f"push しました（{len(names)} 台の変更）" if names else "push しました")
    except Exception as e:  # noqa: BLE001 - 失敗は記録して、システム状態と通知で知らせる
        err = outbound.scrub(mask_url(str(e)))
        logger.warning("外部 Git への push に失敗しました: %s", err)
        result.update(ok=False, error=err[:500], pushed=state.get("pushed"),
                      last_success=state.get("last_success"))
    r.set(STATE_KEY, json.dumps(result, ensure_ascii=False))
    return result
