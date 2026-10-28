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
| 世代管理 | GitPython | コンフィグ差分・履歴 |
| タスクキュー | Celery + Redis | 非同期収集・定期収集（beat が毎分スケジュールを確認） |
| データベース | PostgreSQL 16 | デバイス情報・ユーザー・ログ |
| コンテナ | Podman / Docker | サービス管理 |

## 対応プラットフォーム（Netmiko経由）

- Cisco IOS / IOS-XE / NX-OS
- Juniper JunOS
- Arista EOS
- HP Comware
- Huawei VRP

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

### 起動（本番）

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

- フロントエンドはビルド済みファイルを nginx で配信し、`/api`（WebSocket含む）を backend へ中継します
- 外部公開されるのは `HTTP_PORT`（既定 80）のみです。backend / DB / Redis はコンテナ内部ネットワークのみ
- HTTPS は前段のリバースプロキシ・ロードバランサーで終端してください（ターミナルの通信に機器の操作内容が流れるため、本番では HTTPS 必須）

---

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
- **DBスキーマ**: 今回は既存テーブルの変更はなく、`users` テーブルの追加のみです（起動時に自動作成）。今後カラムを変更する場合は Alembic を導入してください

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
│       │   └── ssh_hostkeys.py  # SSH ホスト鍵検証
│       ├── models/
│       │   ├── __init__.py      # モデル登録
│       │   ├── base.py
│       │   ├── device.py        # Device / ConfigSnapshot / CollectLog / Schedule
│       │   └── user.py          # User
│       ├── api/
│       │   ├── deps.py          # 認証・権限チェック（require）
│       │   ├── auth.py          # ログイン・パスワード変更
│       │   ├── devices.py       # デバイス CRUD + 収集トリガー
│       │   ├── configs.py       # 履歴・差分 API
│       │   ├── tasks.py         # 収集タスクの状態確認
│       │   ├── users.py         # ユーザー管理（管理者のみ）
│       │   ├── terminal.py      # WebSocket SSH ターミナル
│       │   └── schedules.py     # スケジュール CRUD
│       └── services/
│           └── config_service.py # Netmiko + GitPython
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
- **DBマイグレーション**: Alembic の導入
