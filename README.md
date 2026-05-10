# NetConfig Manager

ネットワーク機器のコンフィグ収集・世代管理・SSHターミナルを提供するWebアプリケーション

## アーキテクチャ

| コンポーネント | 技術 | 役割 |
|---|---|---|
| フロントエンド | React + Vite + xterm.js | UI・SSHターミナル |
| バックエンドAPI | FastAPI (Python 3.12) | REST API / WebSocket |
| コンフィグ収集 | Netmiko | マルチベンダーSSH収集 |
| SSHターミナル | Paramiko + WebSocket | インタラクティブシェル |
| 世代管理 | GitPython | コンフィグ差分・履歴 |
| タスクキュー | Celery + Redis | 非同期・定期収集 |
| データベース | PostgreSQL 16 | デバイス情報・ログ |
| コンテナ | Podman / Docker | サービス管理 |

## 対応プラットフォーム（Netmiko経由）

- Cisco IOS / IOS-XE / NX-OS
- Juniper JunOS
- Arista EOS
- HP Comware
- Huawei VRP

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
# .env を編集して本番用パスワード・シークレットキーを設定
```

`.env` ファイル:

```env
POSTGRES_PASSWORD=your_secure_password_here
SECRET_KEY=your_jwt_secret_key_here
```

### 起動

```bash
# Podman の場合
podman-compose up -d

# Docker の場合
docker compose up -d

# ログ確認
podman-compose logs -f backend
```

### アクセス

| サービス | URL |
|---|---|
| フロントエンド | http://localhost:3000 |
| API (Swagger UI) | http://localhost:8000/docs |

デフォルトログイン: `admin` / `admin`（本番では変更必須）

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
sudo firewall-cmd --permanent --add-port=3000/tcp
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --reload
```

### nginx リバースプロキシ（推奨）

```nginx
server {
    listen 80;
    server_name your-server.example.com;

    location / {
        proxy_pass http://localhost:3000;
    }

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## ディレクトリ構成

```
netconfig-manager/
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py              # FastAPI エントリーポイント
│       ├── worker.py            # Celery タスク定義
│       ├── core/
│       │   ├── config.py        # 設定
│       │   └── database.py      # DB セッション
│       ├── models/
│       │   ├── base.py
│       │   └── device.py        # Device / ConfigSnapshot / Schedule
│       ├── api/
│       │   ├── auth.py          # JWT 認証
│       │   ├── devices.py       # デバイス CRUD + 収集トリガー
│       │   ├── configs.py       # 履歴・差分 API
│       │   ├── terminal.py      # WebSocket SSH ターミナル
│       │   └── schedules.py     # スケジュール CRUD
│       └── services/
│           └── config_service.py # Netmiko + GitPython
└── frontend/
    ├── Dockerfile
    ├── package.json
    ├── vite.config.ts
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── index.css
        ├── api/client.ts        # Axios クライアント
        └── pages/
            ├── DevicesPage.tsx  # デバイス管理
            ├── CollectPage.tsx  # コンフィグ収集
            ├── HistoryPage.tsx  # 世代管理・差分
            ├── TerminalPage.tsx # SSH ターミナル
            └── SchedulePage.tsx # スケジュール
```

---

## 今後の拡張ポイント

- **認証強化**: LDAP/AD 連携、MFA、RBAC
- **通知機能**: コンフィグ変更検知時の Slack / メール通知
- **コンプライアンスチェック**: 収集したコンフィグをルールベースで自動チェック
- **バックアップ**: config_repo を外部 Git サーバー (GitLab/Gitea) へ push
- **パスワード管理**: HashiCorp Vault 連携
- **HTTPS**: Let's Encrypt または内部 CA 証明書
