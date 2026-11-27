from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_SECRETS = {"change-me-in-production", "changeme", "secret", "your_jwt_secret_key_here"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore",
        hide_input_in_errors=True,  # 不正な値（鍵・認証情報つき URL）をエラーに出さない
    )

    DATABASE_URL: str = "postgresql+asyncpg://netconfig:changeme@localhost:5432/netconfig"
    REDIS_URL: str = "redis://localhost:6379/0"
    GIT_REPO_PATH: str = "/app/configs"
    MFA_ISSUER: str = "NetConfig Manager"  # 認証アプリに表示する名前（2 段階認証）
    # コンフィグ履歴を外部の Git サーバー（GitLab / Gitea など）へ push する（GIT_EXPORT_URL が空なら無効）
    GIT_EXPORT_URL: str = ""  # 例: https://gitlab.example.local/net/configs.git / git@gitea.local:net/configs.git
    GIT_EXPORT_BRANCH: str = Field(default="main", pattern=r"^[A-Za-z0-9._/-]{1,100}$")
    GIT_EXPORT_USERNAME: str = ""  # HTTPS のユーザー名（GitLab のトークンなら oauth2 など。空なら oauth2）
    GIT_EXPORT_TOKEN: str = ""  # HTTPS のパスワード・アクセストークン（URL には書かない）
    GIT_EXPORT_SSH_KEY: str = ""  # SSH のときの秘密鍵のパス（コンテナの中のパス）
    GIT_EXPORT_KNOWN_HOSTS: str = "/data/ssh/git_known_hosts"  # SSH の相手のホスト鍵（初回に記録）
    GIT_EXPORT_CA_FILE: str = ""  # 社内の CA で発行した証明書の Git サーバーなら、その CA 証明書のパス
    GIT_EXPORT_AUTHOR: str = "NetConfig Manager <netconfig@system.local>"
    GIT_EXPORT_PATH: str = ""  # 書き出し用のリポジトリの場所（空なら GIT_REPO_PATH/_export）
    GIT_EXPORT_DELAY_SEC: int = Field(default=60, ge=0, le=3600)  # 収集で変わってから push するまで（まとめるため）
    GIT_EXPORT_TIMEOUT: int = Field(default=120, ge=10, le=1800)  # push の上限（秒）
    TIMEZONE: str = "Asia/Tokyo"
    # 変更の確認（未確認の変更の一覧・ダッシュボードの「未確認の変更」で数える期間。日数）
    CHANGE_REVIEW_DAYS: int = Field(default=30, ge=1, le=365)

    # --- 認証 ---
    # 必須。デフォルト値は持たせない（未設定・弱い値なら起動時にエラー）
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    # ユーザーが1人もいないときに作成する初期管理者
    ADMIN_USERNAME: str = "admin"
    # 未設定の場合はランダムなパスワードを生成し、起動ログに一度だけ出力する
    ADMIN_PASSWORD: str | None = None

    # --- 機器パスワードの暗号化（Fernetキー）---
    DEVICE_ENCRYPTION_KEY: str

    # カンマ区切り。フロントを同一オリジン（Viteプロキシ / nginx）で配信する場合は空でよい
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    # --- SSH ---
    SSH_TIMEOUT: int = 30
    SSH_AUTH_TIMEOUT: int = 20
    # 機器の応答待ち時間（秒）の既定値。ログイン後のプロンプト待ち・コマンド実行の待ちに使う。
    # 機器ごとに上書き可能（デバイス設定の「応答待ち時間」）
    SSH_READ_TIMEOUT: int = Field(default=120, ge=10, le=600)
    SSH_KNOWN_HOSTS: str = "/data/ssh/known_hosts"
    # tofu  : 初回接続時にホスト鍵を記録し、以後は一致を検証（鍵が変わったら接続拒否）
    # strict: known_hosts に無いホストへの接続を拒否
    SSH_HOST_KEY_POLICY: Literal["tofu", "strict"] = "tofu"

    # --- 監査ログ ---
    # ターミナルの画面出力の記録先（asciicast v2 形式。1セッション1ファイル）
    TERMINAL_LOG_PATH: str = "/data/terminal-logs"
    # 1セッションの記録の上限（バイト）。超えた分は記録しない（ディスクの圧迫を防ぐ）
    TERMINAL_LOG_MAX_BYTES: int = Field(default=20 * 1024 * 1024, ge=1024)
    # 記録を DEVICE_ENCRYPTION_KEY で暗号化して保存する（.cast.enc）。false で従来どおり平文（.cast）
    TERMINAL_LOG_ENCRYPT: bool = True
    # ターミナルの記録を、読める形のテキスト（色や制御文字を除いたもの）でも保存する。監査ログで読む・検索する・渡すため
    TERMINAL_LOG_TEXT: bool = True
    # システムの状態の確認と異常の通知（services/system.py）
    SYSTEM_WATCHDOG_ENABLED: bool = True  # API のプロセスで定期的に確認し、異常を通知する
    SYSTEM_CHECK_INTERVAL_SEC: int = Field(default=60, ge=10)
    # 収集失敗の通知をまとめる時間（秒）。最初の失敗からこの時間に起きた失敗を、通知先ごとに 1 通にまとめる。
    # 0 なら機器ごとにすぐ通知する（これまでの動き）
    NOTIFY_FAILURE_BATCH_SEC: int = Field(default=60, ge=0, le=3600)
    SYSTEM_ALERT_AFTER_MIN: int = Field(default=10, ge=0)  # worker・スケジューラー・Redis の停止がこの分数続いたら通知
    SYSTEM_STALE_DAYS: int = Field(default=7, ge=0)  # この日数以上収集できていない有効な機器を警告（0 で確認しない）
    SYSTEM_CERT_ENDPOINT: str = "frontend:443"  # 期限を確認する HTTPS の接続先（空で確認しない）
    # バックアップ（scripts/backup.sh）の最後の成功からこの時間を過ぎたら警告（0 で確認しない。BACKUP_* のほかの値は
    # ホストの backup.sh だけが .env から読むので、ここには無い）
    BACKUP_STALE_HOURS: int = Field(default=36, ge=0)
    # ログインの失敗回数の制限（services/login_limit.py。0 で制限しない）
    LOGIN_MAX_FAILURES: int = 5  # 同じユーザー名・同じ接続元からの失敗の上限
    LOGIN_MAX_FAILURES_PER_IP: int = 20  # 同じ接続元からの失敗の上限（ユーザー名を問わない）
    LOGIN_FAILURE_WINDOW_MIN: int = 10  # 失敗を数える期間（分）
    LOGIN_LOCK_MIN: int = 15  # 上限に達したときにログインを止める時間（分）
    # API トークン（app/services/api_tokens.py）。false にすると、発行も、発行済みのトークンでの API の利用もできない
    API_TOKENS_ENABLED: bool = True
    API_TOKEN_MAX_DAYS: int = Field(default=365, ge=1, le=365)  # 発行するときに選べる期限の上限（日）
    # コンプライアンスの正規表現の照合にかけられる時間（1回の評価＝ルール × 機器 あたりの合計秒数。ReDoS 対策）
    COMPLIANCE_REGEX_TIMEOUT: float = 2.0
    COMPLIANCE_CHECK_CONCURRENCY: int = Field(default=2, ge=1, le=16)  # 同時に照合するスレッドの数（プロセスごと）
    # 収集時に無視する行（services/ignore_rules.py）の正規表現にかけられる時間（秒）。
    # 1 ルールあたり（全行の合計）と全ルールの合計。超えたらその回は保存せず、収集の失敗（再試行あり）にする
    IGNORE_RULE_TIMEOUT: float = Field(default=1.0, gt=0, le=30)
    IGNORE_TOTAL_TIMEOUT: float = Field(default=5.0, gt=0, le=120)
    # 保持日数（0 なら削除しない）。毎日1回、古いものを削除する
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=365, ge=0)
    TERMINAL_LOG_RETENTION_DAYS: int = Field(default=180, ge=0)
    # アクティビティログ（収集の結果など）の保持日数。スケジュール収集の「変更なし」で件数が増えやすいため短め
    ACTIVITY_LOG_RETENTION_DAYS: int = Field(default=90, ge=0)
    # 収集で変更が無かったときも記録するか（False なら変更あり・失敗などだけ記録）
    ACTIVITY_LOG_UNCHANGED: bool = True

    # --- 定期レポート（services/report.py）。週次は月曜・月次は 1 日に、この時刻（TIMEZONE）以降の最初の判定で送る ---
    REPORT_HOUR: int = Field(default=8, ge=0, le=23)

    # --- コマンド実行（表示コマンドの一括実行。services/command_run.py） ---
    COMMAND_RUN_ENABLED: bool = True
    COMMAND_RUN_MAX_DEVICES: int = Field(default=100, ge=1, le=1000)  # 1 回の実行で対象にできる機器の数
    COMMAND_RUN_CONCURRENCY: int = Field(default=10, ge=1, le=100)  # 1 回の実行の中で同時に接続する機器の数
    COMMAND_RUN_MAX_OUTPUT: int = Field(default=200_000, ge=1000, le=5_000_000)  # 1 コマンドの出力の上限（文字数）
    COMMAND_RUN_MAX_RUN_OUTPUT: int = Field(default=20_000_000, ge=10_000, le=500_000_000)  # 1 回の実行の出力の合計（文字）
    # 終わっていない実行（待機中・実行中）の数の上限。1 人あたりと全体。超えたら新しい実行を 429 で断る
    COMMAND_RUN_MAX_ACTIVE_PER_USER: int = Field(default=2, ge=1, le=100)
    COMMAND_RUN_MAX_ACTIVE: int = Field(default=5, ge=1, le=1000)
    COMMAND_RUN_RETENTION_DAYS: int = Field(default=30, ge=1, le=365)  # 実行結果（出力）を残す日数

    # --- Ping監視 ---
    PING_TIMEOUT: float = Field(default=1.0, gt=0, le=10)  # 1回の PING の応答待ち（秒）
    PING_MAX_TARGETS: int = Field(default=300, ge=1, le=5000)  # 1画面で同時に監視できる数（常時監視の対象の上限も同じ）
    # 常時監視（画面を開いていなくても worker が PING し、結果を残して応答なしを通知する）
    PING_MONITOR_INTERVAL_SEC: int = Field(default=60, ge=10, le=3600)  # PING する間隔
    PING_ALERT_AFTER: int = Field(default=3, ge=1, le=60)  # この回数続けて応答が無ければ「応答なし」として通知
    PING_HISTORY_DAYS: int = Field(default=14, ge=1, le=365)  # 結果を残す日数
    # コンフィグ検索の同時実行数（スレッドプールをログインなどのために残す）
    SEARCH_MAX_PER_USER: int = Field(default=2, ge=1, le=20)  # ユーザーごと
    SEARCH_MAX_CONCURRENT: int = Field(default=4, ge=1, le=30)  # 全体
    # コンテナのイメージがこの日数より前に作られたものなら「システム状態」で注意（setup.sh で取り直していない。0 で確認しない）
    IMAGE_STALE_DAYS: int = Field(default=60, ge=0, le=3650)

    # --- モニタリング（試験導入中。既定は無効） ---
    # FW ルールのヒット数（PAN-OS・FortiGate を SSH で取得）とインタフェースの帯域（SNMP）
    # 機器台帳の自動取得（収集のついでに show version などを実行して、モデル・シリアル番号・OS バージョンを読み取る）
    INVENTORY_ENABLED: bool = True
    INVENTORY_TIMEOUT: int = Field(default=30, ge=5, le=600)  # 台帳用コマンドの応答待ち（秒）。機器の応答待ち時間が短ければそちら
    # 保存し忘れの検出（収集のついでに show startup-config を実行し、running-config と比べる。対象の機種だけ）
    STARTUP_CHECK_ENABLED: bool = True
    # show startup-config の応答待ち（秒）。機器の応答待ち時間が短ければそちら
    STARTUP_CHECK_TIMEOUT: int = Field(default=30, ge=5, le=600)
    MONITORING_ENABLED: bool = False
    MONITOR_INTERVAL_SEC: int = Field(default=300, ge=60, le=3600)  # 帯域を取得する間隔
    MONITOR_RETENTION_DAYS: int = Field(default=30, ge=1, le=400)  # 帯域の記録を残す日数
    MONITOR_FW_INTERVAL_MIN: int = Field(default=60, ge=10, le=1440)  # FW ルールのヒット数を取得する間隔
    MONITOR_UP_ONLY: bool = True  # 稼働中（up）のインタフェースだけ記録する（DB の増え方を抑える）
    MONITOR_PANOS_VSYS: str = "vsys1"  # PAN-OS のヒット数を取得する vsys
    SNMP_TIMEOUT: float = Field(default=3.0, gt=0, le=30)
    SNMP_RETRIES: int = Field(default=1, ge=0, le=5)

    # --- 脆弱性（CVE）とサポート終了日（EOL）の管理（services/vuln_*.py。既定は無効） ---
    # 有効にすると、毎日 1 回、外部（Palo Alto・Fortinet・CISA・endoflife.date）から製品単位の情報を取得して機器の OS バージョンと
    # 照合する。機器名・IP・バージョンは外部へ送らない（取得する URL に含めない）。無効のあいだは外部へ一切つながない
    VULN_ENABLED: bool = False
    VULN_FETCH_HOUR: int = Field(default=4, ge=0, le=23)  # 毎日この時刻（TIMEZONE）以降の最初の判定で取得する
    # 使う情報源（カンマ区切り）。paloalto=Palo Alto の勧告 / fortinet=Fortinet の勧告（FortiOS）/
    # kev=CISA の悪用確認済み一覧 / eol=endoflife.date のサポート終了日
    VULN_SOURCES: str = "paloalto,fortinet,kev,eol"

    # --- 外部への接続（インターネットへの HTTP(S)。app/core/outbound.py） ---
    # 対象: Discord・Slack・Teams の Webhook、メールの OAuth 2.0 のトークンの取得、脆弱性情報の取得。
    # 外部 Git（https://）は git に環境変数で渡す（services/git_export.py）。SMTP・SSH・踏み台・DB・Redis は通さない
    # プロキシ（http://[ユーザー:パスワード@]ホスト:ポート。http:// だけ。空なら直接つなぐ）。
    # ユーザー名・パスワードの記号は URL エンコードで書く（@ → %40 など）。環境変数の HTTPS_PROXY などは見ない
    OUTBOUND_PROXY: str = ""
    # プロキシを通さない宛先（カンマ区切り。ホスト名・ドメイン（後方一致）・IP・CIDR。* はすべて直接）。
    # localhost・ループバック・コンテナ名（db・redis など）は書かなくても常に直接つなぐ
    OUTBOUND_NO_PROXY: str = ""
    # 追加で信頼する CA 証明書（PEM。HTTPS の中身を検査するプロキシの CA など）。ホストの certs-outbound/ に置いた
    # ファイルの名前（コンテナの中では OUTBOUND_CA_DIR の下）か、コンテナの中の絶対パス。空なら追加しない
    OUTBOUND_CA_FILE: str = ""

    # --- 通知 ---
    # 利用者がブラウザで開く URL（例: https://netconfig.example.local）。通知に画面へのリンクを付けるのに使う。空ならリンクなし
    PUBLIC_URL: str = ""

    @field_validator("ADMIN_PASSWORD", mode="before")
    @classmethod
    def _empty_to_none(cls, v):
        # docker-compose で ${ADMIN_PASSWORD:-} のように空文字が渡された場合は未設定扱い
        return v or None

    @field_validator("SECRET_KEY")
    @classmethod
    def _check_secret_key(cls, v: str) -> str:
        if v in _WEAK_SECRETS or len(v) < 32:
            raise ValueError(
                "SECRET_KEY は32文字以上のランダムな値を設定してください "
                "(例: python -c \"import secrets; print(secrets.token_urlsafe(48))\")"
            )
        return v

    @field_validator("DEVICE_ENCRYPTION_KEY")
    @classmethod
    def _check_fernet_key(cls, v: str) -> str:
        from cryptography.fernet import Fernet

        try:
            Fernet(v.encode())
        except Exception as e:  # noqa: BLE001
            raise ValueError(
                "DEVICE_ENCRYPTION_KEY が不正です "
                "(例: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")"
            ) from e
        return v

    @field_validator("OUTBOUND_PROXY")
    @classmethod
    def _check_outbound_proxy(cls, v: str) -> str:
        from app.core import outbound  # 遅く読む（outbound は settings を読む）

        v = v.strip()
        outbound.parse_proxy(v)  # 不正なら ValueError（値・認証情報は文に入れない）
        return v

    @field_validator("OUTBOUND_NO_PROXY")
    @classmethod
    def _check_outbound_no_proxy(cls, v: str) -> str:
        from app.core import outbound

        outbound.parse_no_proxy(v)  # 不正な項目があれば ValueError
        return v.strip()

    @field_validator("OUTBOUND_CA_FILE")
    @classmethod
    def _check_outbound_ca(cls, v: str) -> str:
        from app.core import outbound

        v = v.strip()
        if v:
            outbound.load_ca_file(outbound.resolve_ca_path(v))  # 読めない・PEM でない・証明書が無い → ValueError
        return v

    @property
    def vuln_sources(self) -> list[str]:
        return [x.strip().lower() for x in self.VULN_SOURCES.split(",") if x.strip()]

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]


settings = Settings()
