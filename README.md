# NetConfig Manager

ネットワーク機器のコンフィグ収集・世代管理・SSHターミナルを提供するWebアプリケーション

## アーキテクチャ

| コンポーネント | 技術 | 役割 |
|---|---|---|
| フロントエンド | React + Vite + xterm.js | UI・SSHターミナル |
| バックエンドAPI | FastAPI (Python 3.12) | REST API / WebSocket |
| 認証・認可 | JWT (PyJWT) + bcrypt + RBAC | ログイン・ロール別の権限制御 |
| コンフィグ収集 | Netmiko | マルチベンダーSSH収集 |
| SSHターミナル | Paramiko + WebSocket | インタラクティブシェル |
| 踏み台経由接続 | Paramiko (direct-tcpip) | 踏み台サーバ1段を経由した収集・ターミナル |
| 世代管理 | GitPython | コンフィグ差分・履歴 |
| DBマイグレーション | Alembic | 起動時に自動でスキーマを最新化 |
| タスクキュー | Celery + Redis | 非同期収集・定期収集（beat が毎分スケジュールを確認） |
| データベース | PostgreSQL 16 | デバイス情報・ユーザー・ログ |
| コンテナ | Podman / Docker | サービス管理 |

## 対応プラットフォーム（Netmiko経由）

- Cisco IOS / IOS-XE / NX-OS
- Juniper JunOS
- Arista EOS
- HP Comware
- Huawei VRP
- Palo Alto Networks PAN-OS（設定モードの `show` を set 形式で取得）

収集時、タイムスタンプなど取得のたびに変わる行（`! Last configuration change at ...` 等）は除外してから保存するため、実際に設定が変わったときだけ新しい世代が作られます。除外パターンは `backend/app/services/config_service.py` の `PLATFORMS` で調整できます。

---

## セットアップ (RHEL 10)

### 前提条件

```bash
# Podman + podman-compose のインストール
sudo dnf install -y podman podman-compose git

# または Docker を使用する場合
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

### 環境変数設定

```bash
cp .env.example .env
# .env を編集して以下を設定（未設定のままでは起動しません）
```

| 変数 | 必須 | 説明 |
|---|---|---|
| `POSTGRES_PASSWORD` | ✔ | DB パスワード |
| `SECRET_KEY` | ✔ | JWT 署名鍵（32文字以上）。`python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DEVICE_ENCRYPTION_KEY` | ✔ | 機器パスワード暗号化キー（Fernet）。**紛失すると機器パスワードを復号できなくなります** |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | | 初回起動時に作成する管理者。パスワード未設定ならランダム生成して起動ログに表示 |
| `SSH_HOST_KEY_POLICY` | | `tofu`（既定）/ `strict`。下記「SSHホスト鍵」参照 |

### 起動（開発）

```bash
# Podman の場合
podman-compose up -d

# Docker の場合
docker compose up -d

# 初期管理者のパスワード確認（ADMIN_PASSWORD 未設定の場合）
podman-compose logs backend | grep 初期管理者
```

| サービス | URL |
|---|---|
| フロントエンド | http://localhost:3000 |
| API (Swagger UI) | http://localhost:8000/docs |

ログイン後、サイドバーの「パスワード変更」から管理者パスワードを変更してください。

### 自動セットアップ（AlmaLinux / RHEL 10・おすすめ）

Podman のインストールから `.env` の生成、ビルド・起動、自動起動設定、ファイアウォール開放、起動確認までを対話形式で行います。

```bash
curl -fsSLO https://raw.githubusercontent.com/s-michiaki/netconfig-manager/master/scripts/setup.sh   # またはリポジトリを clone 済みなら scripts/setup.sh
bash setup.sh
```

- `[ ]` 内の値は Enter でそのまま採用されます（初期管理者のパスワードはランダム生成）
- `.env` の秘密値（DBパスワード・JWT鍵・機器パスワード暗号化キー）は自動生成し、`/root/netconfig-manager-backup/` にも控えを保存します
- 2回目以降の実行は「更新」として動作します（`git pull` → 再ビルド → 再起動。既存の `.env` は変更しません）
- 導入前の環境確認だけを行う場合は `bash scripts/check_env.sh`

### 起動（本番）

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

- フロントエンドはビルド済みファイルを nginx で配信し、`/api`（WebSocket含む）を backend へ中継します
- 外部公開されるのは `HTTP_PORT`（既定 80）のみです。backend / DB / Redis はコンテナ内部ネットワークのみ
- HTTPS は前段のリバースプロキシ・ロードバランサーで終端してください（ターミナルの通信に機器の操作内容が流れるため、本番では HTTPS 必須）
- Podman（podman-compose）で手動更新する場合は、イメージ再ビルド後に `podman-compose -f docker-compose.prod.yml up -d --force-recreate` でコンテナを作り直してください（podman-compose は compose ファイルが変わらないと既存コンテナを再作成しません。`setup.sh` は自動で行います）

---

## 機器への SSH 認証

機器ごとにパスワード・SSH 秘密鍵のどちらか、または両方を設定できます（直接接続・踏み台経由のどちらでも使えます）。

- 秘密鍵は OpenSSH 形式（`-----BEGIN OPENSSH PRIVATE KEY-----`）または PEM 形式の RSA / ECDSA / Ed25519。パスフレーズ付きの鍵も使えます
- 両方を設定した場合は鍵 → パスワードの順に試します
- 秘密鍵・パスフレーズは暗号化して保存し、画面・API には鍵の種類と指紋のみ表示します
- Cisco 等で enable が必要な場合は、鍵認証でも「Enableシークレット」を設定してください

## 踏み台サーバ経由の接続

機器に直接SSHできない環境では、踏み台サーバ（1段）を経由して接続できます。

1. 「踏み台サーバ」画面で踏み台を登録する（ホスト・ポート・ユーザー名と、パスワード / 秘密鍵のどちらか、または両方）
2. 「接続テスト」で踏み台への接続・認証を確認する
3. デバイスの編集画面で「接続経路」に踏み台を選び、「到達確認」で踏み台から機器に届くことを確認する

- 秘密鍵は OpenSSH 形式（`-----BEGIN OPENSSH PRIVATE KEY-----`）または PEM 形式の RSA / ECDSA / Ed25519 に対応します。パスフレーズ付きの鍵も使えます。PuTTY の `.ppk` は PuTTYgen で OpenSSH 形式に変換してください
- パスワードと秘密鍵の両方を設定した場合は、鍵 → パスワードの順に試します
- 踏み台側の sshd で TCP フォワーディングが許可されている必要があります（`AllowTcpForwarding yes`、OpenSSH の `ssh -J` と同じ仕組み）。踏み台上でシェルの起動やコマンド実行は行いません
- 踏み台の認証情報（パスワード・秘密鍵・パスフレーズ）は機器パスワードと同様に暗号化して保存し、API の応答には含めません（鍵の種類と指紋のみ表示）
- 踏み台自身のホスト鍵も known_hosts で検証します（`SSH_HOST_KEY_POLICY` に従う）
- デバイスが使用中の踏み台は削除できません
- 踏み台の登録・編集・接続テストは管理者のみ（デバイス編集権限）です

## ユーザーと権限（RBAC）

ユーザーには3つのロールのいずれかを割り当てます。ユーザーの追加・ロール変更・無効化・パスワードリセットは、管理者が「ユーザー管理」画面から行います。

| 権限 | 閲覧者 (viewer) | オペレーター (operator) | 管理者 (admin) |
|---|:-:|:-:|:-:|
| デバイス閲覧 | ✓ | ✓ | ✓ |
| コンフィグ・差分閲覧 | ✓ | ✓ | ✓ |
| スケジュール閲覧 | ✓ | ✓ | ✓ |
| 収集の実行 | | ✓ | ✓ |
| SSHターミナル | | ✓ | ✓ |
| デバイス登録・編集・削除 | | | ✓ |
| スケジュール編集 | | | ✓ |
| ユーザー管理 | | | ✓ |

- 割り当ては `backend/app/core/permissions.py` の `ROLE_PERMISSIONS` だけで定義しています。変更する場合はここを編集してください（画面の表示も `/api/auth/me` が返す権限に従って自動で切り替わります）
- 権限チェックはすべてサーバー側で行います。新しいAPIを追加するときは `dependencies=[Depends(require(Perm.XXX))]` を付けてください（付け忘れはテスト `test_every_protected_route_declares_a_permission` で検出されます）
- ロールの変更・無効化は即座に反映されます（ログイン中のユーザーにも次のリクエストから適用）
- パスワードの変更・リセットを行うと、それ以前に発行されたトークンは無効になります
- 自分自身のロール変更・無効化・削除はできません（有効な管理者が1人もいなくなる操作も拒否されます）
- ユーザー管理操作とターミナルの接続・切断はログに記録されます

## セキュリティ

- **認証**: `/api/auth/token` と `/api/health` 以外の API はすべてログインが必要です。WebSocket ターミナルは接続直後のメッセージでトークンを検証し、ターミナル権限が無ければ切断します
- **機器パスワード**: DB には Fernet で暗号化して保存します。旧バージョンで平文保存されていたものは backend 起動時に自動で暗号化されます
- **SSHホスト鍵**: known_hosts を `ssh_data` ボリューム（`/data/ssh/known_hosts`）で backend と worker が共有します
  - `tofu`: 初回接続時に鍵を記録し、以後は一致しなければ接続を拒否（機器を入れ替えた場合は known_hosts から該当行を削除）
  - `strict`: known_hosts に事前登録したホストにのみ接続
- **収集したコンフィグ**: パスワードハッシュや SNMP コミュニティ等が含まれるため、`config_repo` ボリュームのアクセス権・バックアップ先の扱いに注意してください

---

## 旧バージョンからの移行

- **Gitリポジトリ**: 機器名ディレクトリ（`/app/configs/<機器名>`）から device_id ディレクトリ（`/app/configs/<device_id>`）へ、backend 起動時に自動で移動します
- **機器パスワード**: 起動時に自動で暗号化されます（`DEVICE_ENCRYPTION_KEY` を必ず控えてください）
- **ユーザー**: 旧版のハードコードされた `admin/admin` は廃止しました。初回起動時に `ADMIN_USERNAME` / `ADMIN_PASSWORD` で作成されます
- **DB パスワード**: 既存の `postgres_data` ボリュームがある場合、`.env` の `POSTGRES_PASSWORD` には初回作成時の値（旧デフォルトは `changeme`）を設定してください
- **DBスキーマ**: v1.3 から Alembic でスキーマを管理します。backend 起動時に自動で最新化され、Alembic 導入前（create_all で作成）の既存DBも自動で引き継ぎます（データはそのまま）。手動で実行する場合は `docker compose exec backend python -m app.core.migrate`
- **スキーマを変更するとき**: モデルを変更したら `docker compose exec backend alembic revision --autogenerate -m "説明"` でマイグレーションを作成し、`backend/migrations/versions/` をコミットしてください

---

## テスト

PostgreSQL / Redis 不要（SQLite・fakeredis・テスト用SSHサーバーを使用）。

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

コンテナ内で実行する場合:

```bash
docker compose run --rm backend sh -c "pip install -r requirements-dev.txt && pytest"
```

---

## RHEL 10 本番設定

### SELinux 対応

```bash
# Podman でボリュームマウントする場合は :z ラベルを付与
# docker-compose.yml の volumes に追加:
# - ./backend:/app:z
# - config_repo:/app/configs:z
```

### systemd サービス化

```bash
# podman-compose を systemd サービスとして登録
sudo podman generate systemd --new --name netconfig-manager \
  > /etc/systemd/system/netconfig-manager.service
sudo systemctl enable --now netconfig-manager
```

### firewalld ポート開放

```bash
# 本番構成（nginx）は HTTP ポートのみ開放
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

---

## ディレクトリ構成

```
netconfig-manager/
├── docker-compose.yml           # 開発用
├── docker-compose.prod.yml      # 本番用（nginx 配信）
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── requirements-dev.txt     # テスト用
│   ├── alembic.ini              # DBマイグレーション設定
│   ├── migrations/versions/     # マイグレーション
│   ├── tests/                   # pytest
│   └── app/
│       ├── main.py              # FastAPI エントリーポイント・起動時の移行処理
│       ├── worker.py            # Celery タスク定義（収集・スケジュール実行）
│       ├── core/
│       │   ├── config.py        # 設定
│       │   ├── database.py      # DB セッション
│       │   ├── security.py      # パスワードハッシュ・JWT
│       │   ├── permissions.py   # ロールと権限の定義（RBAC）
│       │   ├── crypto.py        # 機器パスワード暗号化
│       │   ├── ssh_hostkeys.py  # SSH ホスト鍵検証
│       │   ├── ssh_keys.py      # SSH 秘密鍵の読み込み（機器・踏み台共通）
│       │   ├── ssh_jump.py      # 踏み台経由の接続
│       │   └── migrate.py       # 起動時のDBマイグレーション
│       ├── models/
│       │   ├── __init__.py      # モデル登録
│       │   ├── base.py
│       │   ├── device.py        # Device / JumpHost / ConfigSnapshot / CollectLog / Schedule
│       │   └── user.py          # User
│       ├── api/
│       │   ├── deps.py          # 認証・権限チェック（require）
│       │   ├── auth.py          # ログイン・パスワード変更
│       │   ├── devices.py       # デバイス CRUD + 収集トリガー
│       │   ├── jump_hosts.py    # 踏み台サーバ CRUD + 接続テスト
│       │   ├── configs.py       # 履歴・差分 API
│       │   ├── tasks.py         # 収集タスクの状態確認
│       │   ├── users.py         # ユーザー管理（管理者のみ）
│       │   ├── terminal.py      # WebSocket SSH ターミナル
│       │   └── schedules.py     # スケジュール CRUD
│       └── services/
│           ├── config_service.py # Netmiko + GitPython
│           └── connection.py    # 接続情報（踏み台含む）の読み出し
└── frontend/
    ├── Dockerfile               # dev / prod マルチステージ
    ├── nginx.conf               # 本番用
    ├── package.json
    ├── package-lock.json
    ├── tsconfig.json
    ├── vite.config.ts
    └── src/
        ├── main.tsx
        ├── App.tsx              # ルーティング・ログインガード
        ├── index.css
        ├── auth.tsx             # ログインユーザー・権限（useAuth / RequirePerm）
        ├── api/client.ts        # Axios クライアント・認証
        └── pages/
            ├── LoginPage.tsx    # ログイン
            ├── DevicesPage.tsx  # デバイス管理
            ├── JumpHostsPage.tsx # 踏み台サーバ
            ├── CollectPage.tsx  # コンフィグ収集
            ├── HistoryPage.tsx  # 世代管理・差分
            ├── TerminalPage.tsx # SSH ターミナル
            ├── SchedulePage.tsx # スケジュール
            └── UsersPage.tsx    # ユーザー管理
```

---

## 今後の拡張ポイント

- **認証強化**: LDAP/AD 連携、MFA、機器グループ単位の権限
- **監査ログ**: ターミナル操作の記録（現在は接続・切断のみログ出力）
- **通知機能**: コンフィグ変更検知時の Slack / メール通知
- **コンプライアンスチェック**: 収集したコンフィグをルールベースで自動チェック
- **バックアップ**: config_repo を外部 Git サーバー (GitLab/Gitea) へ push
- **パスワード管理**: HashiCorp Vault 連携
- **踏み台の多段化**: 2段以上の踏み台経由（現在は1段まで）
