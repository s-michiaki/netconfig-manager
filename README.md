# NetConfig Manager

ネットワーク機器のコンフィグ収集・世代管理・SSHターミナルを提供するWebアプリケーション

## アーキテクチャ

| コンポーネント | 技術 | 役割 |
|---|---|---|
| フロントエンド | React + Vite + xterm.js | UI・SSHターミナル（画面ごとにファイルを分け、開いたときに読み込む） |
| バックエンドAPI | FastAPI (Python 3.12) | REST API / WebSocket |
| 認証・認可 | JWT (PyJWT) + bcrypt + RBAC | ログイン・ロール別の権限制御 |
| コンフィグ収集 | Netmiko | マルチベンダーSSH収集 |
| SSHターミナル | Paramiko + WebSocket | インタラクティブシェル |
| 踏み台経由接続 | Paramiko (direct-tcpip) | 踏み台サーバ1段を経由した収集・ターミナル |
| 世代管理 | GitPython | コンフィグ差分・履歴 |
| DBマイグレーション | Alembic | 起動時に自動でスキーマを最新化 |
| 通知 | Webhook（Discord / Slack / Teams）・smtplib（メール。SMTP Auth・OAuth 2.0） | 変更・違反・収集失敗・システムの異常などの通知 |
| Ping監視 | icmplib + WebSocket / Celery | 登録機器・指定IPへの死活監視（deadman 風）と、常時監視（結果の記録・応答なしの通知） |
| モニタリング（試験導入） | pysnmp + Netmiko | SNMP による帯域の使用率・FW ルールのヒット数（既定は無効） |
| タスクキュー | Celery + Redis | 非同期収集・定期収集・定期コンプライアンスチェック（beat が毎分スケジュールを確認） |
| データベース | PostgreSQL 16 | デバイス情報・ユーザー・ログ |
| コンテナ | Podman / Docker | サービス管理 |

## 対応プラットフォーム（Netmiko経由）

Netmiko のドライバーがあり、コンフィグを取得するコマンドが決まっている機種に対応しています（56 種類）。一覧と取得コマンド・除外する行は `backend/app/services/config_service.py` の `PLATFORMS` で一元管理しており、画面の選択肢・表示名・構成図の既定アイコンもここから取得します（`GET /api/devices/platforms`）。

| メーカー | 機種（取得コマンド） |
|---|---|
| Cisco | IOS / IOS-XE / NX-OS / IOS-XR / ASA（`show running-config`）、Small Business Sx200・Sx300、WLC（`show run-config commands`）、SD-WAN（Viptela） |
| Juniper | JunOS（`show configuration \| display set`）、ScreenOS（`get config`） |
| Fortinet | **FortiGate / FortiOS**（`show`） |
| Palo Alto Networks | PAN-OS（設定モードの `show` を set 形式で取得） |
| Allied Telesis | **AlliedWare Plus**（`show running-config`。ログイン後に自動で enable） |
| 国内メーカー | Yamaha RTX / NVR / SWX（`show config`）、APRESIA AEOS |
| Arista / HPE・Aruba / Huawei / Dell | EOS、Comware・ProCurve・OS-Switch・AOS-CX・ArubaOS、VRP・VRP V8、OS10・OS9・OS6 |
| Extreme・Brocade・Ruckus | EXOS・VOSS・ERS・SLX・NOS（VDX）・NetIron・FastIron（ICX） |
| ルーター・FW・その他 | MikroTik RouterOS（`/export`）、VyOS、Ubiquiti EdgeRouter・EdgeSwitch、Nokia SR OS、Check Point Gaia、Hillstone、Alcatel-Lucent OmniSwitch、A10、Citrix NetScaler、NVIDIA / Mellanox Onyx、Ruijie、ZTE、TP-Link JetStream、NETGEAR、Broadcom ICOS、D-Link、Zyxel、IP Infusion OcNOS、Centec、FS、Eltex |

機種ごとの注意（機器登録画面にも表示されます）:

- **FortiGate**: Netmiko がページングを無効化するため、収集中だけ `config system console` の `output` を `standard` にし、終了時に元へ戻します。そのため収集用の管理者アカウントにはシステム設定の書き込み権限が必要です（常に `standard` にしておけば設定は変わりません）。`ENC` で表示される可逆暗号化の値（PSK 等）と秘密鍵は取得のたびに変わるため伏せ字にして保存します（管理者パスワードのハッシュ `SH2` / `PB2` はそのまま）。`#conf_file_ver` の行は除外します
- **AlliedWare Plus**: `show running-config` には特権モードが必要なため、Enable パスワードが未設定でも自動で `enable` します。旧 CentreCOM（AlliedWare、`Manager >` のプロンプト）は Netmiko のドライバーが無いため未対応です
- **Yamaha**: `show config` に管理者モードが必要な機種があるため、Enable パスワード欄に administrator のパスワードを設定してください。`console character` が sjis の場合、日本語の部分は正しく取得できません
- 今回追加した機種は、疑似機器（テスト用 SSH サーバー）で取得の流れを確認したもので、実機での確認はしていません。動かない機種があれば、取得コマンドや除外パターンを `PLATFORMS` で調整してください

収集時、タイムスタンプなど取得のたびに変わる行（`! Last configuration change at ...` 等）は除外してから保存するため、実際に設定が変わったときだけ新しい世代が作られます。除外パターンは `backend/app/services/config_service.py` の `PLATFORMS` で調整できます。機種のコードを変えずに、画面から行を追加することもできます（下の「収集時に無視する行」）。

ページング（`--More--` 等）はログイン時に自動で無効化します（`terminal length 0` / `screen-length` / `set cli pager off` / `console lines infinity` 等）。権限不足などで無効化できず出力が途中で止まった場合は、タイムアウトを待たずに収集エラーとし、不完全なコンフィグは保存しません。

---

## セットアップ

### 対応 OS

| OS | 状態 | 導入・運用の道具 |
|---|---|---|
| AlmaLinux 10 | **確認済み** | dnf（podman-compose は EPEL）・firewalld・SELinux |
| Ubuntu 24.04 LTS | スクリプトは対応済み。**実機での導入は未確認** | apt・ufw・AppArmor |
| RHEL 10・Rocky Linux 10・CentOS Stream 10 | 同じ手順で動く想定（AlmaLinux 以外は実機で確認していません。判定は ok） | dnf（podman-compose は EPEL）・firewalld・SELinux |
| Debian 12 以降 | 未確認（Ubuntu と同じ手順で試します。実行時に警告を出します） | apt・ufw・AppArmor |
| 上記以外 | 対象外 | `setup.sh` は dnf が無ければ止まります。`check_env.sh` は警告を出します |

- `scripts/` のスクリプト（`setup.sh`・`check_env.sh`・`import_cert.sh`・`backup.sh`・`restore.sh`・`collect_logs.sh`）は、同じものを両方の OS で使います。OS の判定と、OS ごとに違う操作（パッケージの導入・ファイアウォール）は `scripts/lib/os.sh` の 1 か所にまとめています（`/etc/os-release` の `ID`・`VERSION_ID`・`ID_LIKE` で判定）
- AlmaLinux / RHEL 10 系での動きは変えていません（分岐を足しただけです）。ただし `setup.sh` だけをダウンロードして初回に実行したときは、リポジトリが無く OS の共通部品（`lib/os.sh`）を読めないため、先に git を入れてリポジトリを取得してから読み込みます（取得の前に、`/etc/os-release` で明らかに対象外の OS なら止まります。リポジトリの中の `setup.sh` も、対象外の OS なら、パッケージを入れる前に止まります）
- **Ubuntu 24.04 LTS は、偽のコマンドを使ったテスト（`backend/tests/test_os_scripts.py`・`backend/tests/test_setup_script.py`）で動きを確かめただけで、実機での導入・更新は確認していません**。実機で試すときは、下の「Ubuntu 24.04 LTS で使う」の確認項目を順に見てください
- 画面の左下には、アプリの版だけを表示します（OS 名は表示しません）

### 前提条件

```bash
# Podman + podman-compose のインストール（AlmaLinux / RHEL 10）
sudo dnf install -y podman podman-compose git

# Ubuntu 24.04 LTS の場合
sudo apt-get update
sudo apt-get install -y podman podman-compose git netavark aardvark-dns uidmap

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
| `DEVICE_ENCRYPTION_KEY` | ✔ | 機器パスワード暗号化キー（Fernet。機器・踏み台・認証情報プロファイルの認証情報に使用）。**紛失すると機器パスワードを復号できなくなります** |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | | 初回起動時に作成する管理者。パスワード未設定ならランダム生成して起動ログに表示 |
| `SSH_HOST_KEY_POLICY` | | `tofu`（既定）/ `strict`。下記「SSHホスト鍵」参照 |
| `API_TOKENS_ENABLED` | | `true`（既定）/ `false`。`false` にすると API トークンの発行も、発行済みのトークンでの利用もできなくなる（「API トークン」参照） |
| `API_TOKEN_MAX_DAYS` | | API トークンの期限として選べる日数の上限（1〜365、既定 365） |

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

### 自動セットアップ（AlmaLinux / RHEL 10・Ubuntu 24.04 LTS・おすすめ）

Podman のインストール（RHEL 系は dnf、Ubuntu は apt-get）から `.env` の生成、ビルド・起動、自動起動設定、ファイアウォール開放、起動確認（画面の応答に加えて、収集を実行する worker・スケジューラーが動くかまで）を行います（初回は対話形式）。

```bash
curl -fsSLO https://raw.githubusercontent.com/s-michiaki/netconfig-manager/master/scripts/setup.sh   # またはリポジトリを clone 済みなら scripts/setup.sh
bash setup.sh
```

- `[ ]` 内の値は Enter でそのまま採用されます（初期管理者のパスワードはランダム生成）
- `.env` の秘密値（DBパスワード・JWT鍵・機器パスワード暗号化キー）は自動生成し、`/root/netconfig-manager-backup/` にも控えを保存します
- 2回目以降の実行は「更新」として動作します（`git pull` → イメージの取り直し → 再ビルド → 再起動。既存の `.env` は変更しません）
  - PostgreSQL・Redis のイメージと、ビルドの土台（Python・Node.js・nginx）のイメージを毎回取り直し、セキュリティ修正を取り込みます（同じタグでも中身は更新されるため）。取り直せない（インターネットに出られない等）ときは、警告を出して手元のイメージで続けます。使われなくなった古いイメージは消します（`podman image prune`）
  - backend・frontend のビルドでは、OS のパッケージも更新します（`apt-get upgrade` / `apk upgrade`。公式のイメージが作り直される前に出た修正を取り込むため。ビルドのキャッシュがあっても日に 1 回はやり直します）
  - `.env` は、更新で変えるものがあっても、最初に変える前に `/root/netconfig-manager-backup/` へバックアップします。足りないキー（`HTTP_PORT` など）を足すときは、`.env` の末尾が改行で終わっていなければ改行を補ってから別の行として足します（既存の行は変えません）。ポートは、前後の引用符と CR（CRLF の `.env`）を除いて読みます（`.env` は書き換えません）
  - 取り直したイメージの作成日時は「システム状態」の「コンテナのイメージ」に表示します。OS や PostgreSQL などのセキュリティ修正を取り込むため、**月に 1 回程度は `setup.sh` を実行してください**
  - 更新では何も聞きません。ポートは `.env` の `HTTP_PORT`・`HTTPS_PORT` をそのまま使います
  - ポートや IP アドレスを聞き直したいときは `bash scripts/setup.sh --reconfigure`
  - `git pull` で `setup.sh` 自身が更新されたときは、新しい内容で自動的に最初からやり直します（2 回実行する必要はありません）
- 導入前の環境確認だけを行う場合は `bash scripts/check_env.sh`
- OS ごとの違い:

| 項目 | AlmaLinux / RHEL 10 系 | Ubuntu 24.04 LTS（実機未確認） |
|---|---|---|
| パッケージ | `dnf install -y git podman podman-compose curl`（podman-compose のときは先に `epel-release`） | `apt-get update` のあと `DEBIAN_FRONTEND=noninteractive apt-get install -y git podman podman-compose curl`。コンテナ同士が名前（`db`・`redis`）で引けるよう、`netavark`・`aardvark-dns`・rootless 用の `uidmap` も未導入なら入れます |
| ファイアウォール | firewalld が動いているときだけ（80・443 は service、それ以外は port） | ufw が有効（`ufw status` が `active`）のときだけ `ufw allow <ポート>/tcp`。無効なら何もしません |
| SELinux / AppArmor | SELinux（`getenforce` があるときだけ確認。compose の `:Z` はそのまま） | AppArmor（`aa-status` があれば `collect_logs.sh` に状態と拒否の記録を出します。compose の `:Z` は SELinux が無くても無視されるのでそのまま） |
| 時刻同期 | chronyd | systemd-timesyncd または chrony（`timedatectl` の同期状態で判定） |
| 再起動後の自動起動 | `podman-restart.service` を有効にする（失敗したら止まる） | 同じ。ただし Ubuntu 24.04 のユニットは `restart-policy=always` のコンテナしか起動しないため、`unless-stopped` も起動するドロップインを置きます（下記）。ユニットが無い・有効にできないときは**警告して続けます** |
| gpg の案内（バックアップの暗号化） | `gnupg2` | `gnupg` |
| 定期バックアップ（systemd タイマー） | `/etc/systemd/system/netconfig-backup.{service,timer}` | 同じ（パスの違いはありません） |

### プロキシ環境での導入（`setup.sh`）

直接インターネットへ出られないサーバーでは、`setup.sh` の外へ出るコマンド（git の clone・pull、dnf / apt-get、`podman pull`、コンテナのビルドの中の apt-get・pip・npm・apk）をプロキシに通します。設定はアプリと同じ `.env` の `OUTBOUND_PROXY`・`OUTBOUND_NO_PROXY`・`OUTBOUND_CA_FILE`（意味は「外部への接続（プロキシ・組織の CA）」）で、`.env` に無い・空のときだけ実行時の環境変数（`https_proxy` → `HTTPS_PROXY` → `http_proxy` → `HTTP_PROXY`、`no_proxy` / `NO_PROXY`）を使います。**設定しなければ、今までどおり直接つなぎます**。

**初回の導入**（`.env` がまだ無い）は環境変数で渡します。渡した値は `.env` を作るときに書き込み、以後の更新とアプリが使います（空の値は書きません）。

```bash
# 認証なし
export https_proxy=http://proxy.example.test:3128
bash setup.sh

# 認証あり: パスワードをコマンドの履歴・プロセスの一覧に残さないよう、画面に出さずに読み込んでから実行する
read -rsp 'プロキシの URL（http://ユーザー:パスワード@ホスト:ポート）: ' https_proxy; echo; export https_proxy
bash setup.sh
unset https_proxy
```

- `sudo https_proxy=http://… bash setup.sh` の形でも動きますが、URL がコマンドの履歴に残り、実行中は `sudo` の引数としてプロセスの一覧（`ps`）から見えます。認証ありのときは上の書き方にしてください（root で動かすなら、`export` したあと `sudo --preserve-env=https_proxy bash setup.sh`）
- プロキシを通さない宛先: `export no_proxy=intranet.example.test,10.0.0.0/8`（`OUTBOUND_NO_PROXY` として保存）。`localhost`・`127.0.0.1`・`::1`・コンテナ名（`db`・`redis`・`backend`・`worker`・`beat`・`frontend`）は書かなくても常に入れます（保存もしません）
  - 書ける項目（アプリと同じ規則。カンマか空白で区切る）: ホスト名（`intranet.example.test`）、ドメイン（`.example.test`。`*.example.test` は `.example.test` とみなす）、IP・CIDR（`10.0.0.0/8`・`2001:db8::/32`・`[::1]`）、`*`（すべて直接）。大文字は小文字に、末尾の `.` は外します
  - 書けない項目: ポートつき（`host.example.test:8080`・`[::1]:80`）、`<local>`、途中の `*`（`10.*`・`*example.test`）、英字以外の文字のドメイン。**環境変数から取り込むときは、これらを除いて保存し、何を除いたかを画面に出します**（そのまま保存すると backend・worker が起動時の検査で止まるため）。`.env` の `OUTBOUND_NO_PROXY` に書けない項目があるときは、どのキーのどの項目かを示して、コンテナを作り直す前に止まります
  - `.example.test` の意味は道具で違います（アプリは「そのドメインと配下」、podman（Go）などは「配下だけ」）。`setup.sh` が各コマンドに渡す `no_proxy` には、`.example.test` に `example.test` も足します。手で設定するときに両方へ効かせたいなら `example.test,.example.test` と 2 つ書いてください
- HTTPS の中身を検査するプロキシ（組織の CA）: CA（PEM）のファイルを `export OUTBOUND_CA_FILE=/root/example-corp-ca.pem` で渡すと、ソースの取得のあとで `certs-outbound/outbound-ca.pem` に写し、`.env` に `OUTBOUND_CA_FILE=outbound-ca.pem` を書きます。パッケージの導入（dnf / apt-get）と `podman pull` は OS の信頼ストアを使うので、**先に OS へ登録してください**（下の「CA を OS に登録する」。git の導入・clone のためにも要ります）
  - CA のファイルに秘密鍵（`PRIVATE KEY`）が入っていると止まります（証明書だけのファイルにしてください）。各証明書は `openssl x509` で読めるかを確かめます（openssl が無ければ形式だけを確かめ、そのことを表示します）。写すとき（`certs-outbound/`・ビルド用の `build-ca/`・git 用の束）は、`CERTIFICATE` のブロックだけを書き出します
- 形式は `http://[ユーザー:パスワード@]ホスト:ポート` だけです。ユーザー名があるならパスワードも要ります（空のパスワードは `http://ユーザー:@ホスト:ポート` と `:` を付けて書く。アプリと同じ）。ユーザー名・パスワードの記号は URL エンコードで書きます（「外部への接続」の表）
  - **`.env` の `OUTBOUND_PROXY` が正しくないとき**は、値を表示せずに理由とキーだけを出して止まります（アプリも起動できないため。ソースの更新・ビルド・コンテナの作り直しの前＝今のコンテナが動いているうちに止めます）
  - **環境変数の値が正しくないとき**（スキームの無い `proxy.example.test:3128`・`https://`・`socks5://`・ユーザー名だけ など。サーバーの `/etc/environment` などにあるもの）は止めません。「環境変数のプロキシ（形式が違うため）は使いません。今までどおり直接つなぎます」と警告して、今までと同じ動きにします（スキームの無い値を `http://` とみなすような読み替えはしません）。その結果つながらなかったときは、失敗の案内でもそのことを示します。使うには `.env` に `OUTBOUND_PROXY=http://…` を書いてください

**更新**では `.env` の値を使います。古い導入で `.env` にキーが無いときに環境変数で渡すと、その値を `.env` の末尾に足します（「.env に保存しました: OUTBOUND_PROXY=http://\*\*\*@proxy.example.test:3128」のように伏せ字で表示。既存の行は書き換えません）。`.env` に空の値（`OUTBOUND_PROXY=`）で書いてあるときは足さず、その回の導入・更新だけ環境変数を使います（アプリは直接つなぐので、アプリにも使うときは `.env` に書いてください）。`.env` に廃止した `VULN_HTTPS_PROXY` が残っていれば、`OUTBOUND_PROXY` へ移すよう 1 行出します。

**どのコマンドに、どう渡すか**

| コマンド | プロキシ | 追加の CA |
|---|---|---|
| git の clone・pull | 環境変数 | OS の信頼ストアと追加の CA を束ねた一時ファイルを `GIT_SSL_CAINFO` で渡す（終了時に消す。OS の設定は変えない） |
| dnf / apt-get・`podman pull` | 環境変数 | OS の信頼ストア（利用者が登録する。未登録なら手順を表示） |
| コンテナのビルド（`podman-compose build`） | `podman build` が既定で RUN の中にだけ渡す（イメージの環境変数・履歴には保存しない） | `setup.sh` がビルドの直前に `backend/build-ca/`・`frontend/build-ca/` へ写し、Dockerfile が apt-get・pip（OS の信頼ストア）・npm（`NODE_EXTRA_CA_CERTS`）・apk（`SSL_CERT_FILE`）に使わせる。backend のイメージには CA が入る（実行時のアプリも使う。証明書は秘密ではない）。frontend のイメージのファイルとしては残さない |
| コンテナの起動（`podman-compose up`） | **渡さない**（podman は既定で、起動したプロセスのプロキシの環境変数をコンテナにも入れるため、外してから起動する。アプリは `.env` の `OUTBOUND_PROXY` だけを使う） | — |

- `sudo` は環境変数を落とすので、値ではなく**名前**で引き継ぎます（`sudo --preserve-env=http_proxy,https_proxy,…`。コマンドラインと sudo のログに値が出ない）。sudo の設定で名前の引き継ぎが許されないとき（`timestamp_timeout=0` などで確かめの `sudo -n` が通らないときも）は、値を自分だけが読める一時ファイル（0600。終了時に消す）に書き、`sudo bash -c '. <ファイル>; …'` で root に読ませます（コマンドラインと sudo のログ（journal・`/var/log/auth.log`・`/var/log/secure`）にはファイルのパスしか出ません）。`sudo env 変数=値` の形は使いません
- `setup.sh` の画面に出すのは `http://***@proxy.example.test:3128` の形だけです。`bash -x setup.sh` で実行しても、値を扱うところでは表示を止めます。`podman-compose build`・`up` の出力（podman-compose 1.0.6 は、実行する `podman run … -e SECRET_KEY=… -e OUTBOUND_PROXY=…` をそのまま表示します）は伏せ字のフィルタに通し、秘密らしい名前のキー（`PASSWORD`・`SECRET`・`KEY`・`TOKEN`・`PROXY` など）の値と `scheme://ユーザー:パスワード@` の形を伏せます（終了コードは podman-compose のもの）
- ただし、アプリ用の `OUTBOUND_PROXY` は、ほかの秘密（`SECRET_KEY`・DB のパスワードなど）と同じくコンテナの環境変数として渡すので、`podman run` の実行中の引数（プロセスの一覧）と `podman inspect` には含まれます（どちらも root だけが見られます）。`env_file` で渡す形への移行は、既存の秘密すべてに及ぶので別の作業にします
- CA がビルドで使われなくなったとき（`OUTBOUND_CA_FILE` を空にした）は、次の `setup.sh` が `build-ca/` の写しを消します（`build-ca/` は README.md だけになり、CA なしと同じビルドになります）

**CA を OS に登録する**（`setup.sh` は OS の信頼の設定を変えません。追加の CA があって OS に登録されていないとき＝CA の証明書が OS の束に含まれていないときは、OS に合わせた手順を表示します。失敗したときにも同じ案内を出します）

```bash
# AlmaLinux / RHEL
sudo cp /opt/netconfig-manager/certs-outbound/outbound-ca.pem /etc/pki/ca-trust/source/anchors/netconfig-outbound-ca.pem
sudo update-ca-trust
# Ubuntu（拡張子は .crt。1 つのファイルに 1 つの証明書にする）
sudo cp /opt/netconfig-manager/certs-outbound/outbound-ca.pem /usr/local/share/ca-certificates/netconfig-outbound-ca.crt
sudo update-ca-certificates
```

`podman pull` だけに使わせるなら、レジストリごとに `/etc/containers/certs.d/<レジストリ>/ca.crt` に置く方法もあります。

**確かめ方**

- `sudo bash scripts/check_env.sh`: 「インターネット接続」に、使うプロキシ（伏せ字）と出どころ、追加の CA が OS に登録済みか、宛先（Docker Hub・PyPI・npm・Debian・GitHub）ごとの結果を出します。失敗は「プロキシに接続できません」「プロキシのホスト名を解決できません」「プロキシの認証に失敗しました（407）」「プロキシが接続を拒否しました（CONNECT に HTTP 403）」「証明書を検証できません」（CA の案内つき）に切り分けます
- イメージにプロキシ（認証情報）が残っていないこと（何も出なければよい）:

```bash
for i in $(sudo podman images --format '{{.Repository}}:{{.Tag}}' | grep -E 'backend|worker|beat|frontend'); do
  sudo podman history --no-trunc "$i" | grep -i proxy
  sudo podman inspect "$i" | grep -i proxy
done
# 動いているコンテナに http_proxy などが入っていないこと（アプリ用の OUTBOUND_PROXY は入ります）
for c in $(sudo podman ps -q); do sudo podman inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$c" | grep -iE '^(https?|no)_proxy='; done
```

**限界**

- `setup.sh` だけをダウンロードした初回は、ソースの取得（git の導入と clone）までは環境変数のプロキシを名前で引き継ぐだけです（形式の検査・追加の CA の git への受け渡しは、取得のあと）。HTTPS を検査するプロキシでは、先に OS へ CA を登録してください
- **この版へ初めて更新するとき**は、古い `setup.sh` が `git pull` します。リポジトリの所有者が実行する人と違う（`sudo -u <所有者>` で pull する）と、古い `setup.sh` はプロキシの環境変数を引き継げません。その場合は、`export https_proxy=…` したうえで所有者として `git -C /opt/netconfig-manager pull --ff-only` を実行してから `setup.sh` を実行してください
- プロセスの環境変数（`/proc/<PID>/environ`）は、同じユーザーと root からは見えます（ビルドの RUN の中も同じ）。アプリ用の `OUTBOUND_PROXY` は、DB のパスワードなどと同じく、コンテナの `podman inspect` で root から見えます
- frontend の最終イメージ（nginx）では CA のファイルを消しますが、`COPY` の層（下の層）には残ります（CA の証明書は公開の情報です）
- ビルドへの CA の渡し方（apt-get・pip・npm・apk）と、イメージ・履歴にプロキシが残らないことは、Ubuntu 24.04 と同じ Podman 4.9・podman-compose 1.0.6 と HTTPS を検査するプロキシで確かめています。`setup.sh` 全体の流れは偽のコマンドのテストで確かめており、実機での通しの導入（AlmaLinux 10 の Podman 5・SELinux、Ubuntu 24.04）は未確認です

### Ubuntu 24.04 LTS で使う（実機未確認）

自動セットアップと同じ `bash scripts/setup.sh` で導入・更新できるように作っていますが、**実機での導入は確認していません**。前提と、初めて試すときの確認項目です。

- **Podman は 4.9 系、podman-compose は 1.0 系**（Ubuntu 24.04 のパッケージ）です。RHEL 10 の Podman 5 系・EPEL の podman-compose より古く、`podman-compose up -d --force-recreate`・`down -v`・`build` の動きや、コンテナのラベル（`com.docker.compose.service`）の付き方に差が出る可能性があります。うまく動かないときは `collect_logs.sh` の出力を添えて報告してください
- **ufw**: 有効なときだけ `setup.sh`・`import_cert.sh` が `ufw allow <ポート>/tcp` を実行します。ufw が無効な環境では何もしません（Ubuntu の既定は無効です）。なお `check_env.sh` の ufw の確認は `80/tcp ALLOW` のような個別の規則だけを見るため、複数ポートの規則（`80,443/tcp`）やアプリのプロファイル（`Nginx Full` など）で許可していると「未許可」の警告になることがあります（警告だけで、導入は止まりません。`sudo ufw status` で実際の許可を確かめてください）。有効にするときは、先に SSH を許可（`sudo ufw allow OpenSSH`）してから有効化してください
- **AppArmor**: Podman のコンテナは標準のプロファイル（`containers-default`）で動きます。コンテナが不許可で止まったときは `sudo journalctl -k | grep -i apparmor` を見てください（`collect_logs.sh` は `system/apparmor.txt`・`system/apparmor-denials.txt` に出します）。SELinux の `:Z` は Podman が無視するので、compose の書き換えは要りません
- **rootless は使いません**: 本番の構成（`docker-compose.prod.yml`）は 80・443 番を使うため、`setup.sh` は `sudo podman` で動かします（RHEL と同じ）
- **podman-restart.service**: Ubuntu 24.04 の podman 4.9.3 にはユニットが入っていますが、`ExecStart` が `podman start --all --filter restart-policy=always` だけで、`docker-compose.prod.yml` の `restart: unless-stopped` のコンテナは再起動後に起動しません。`setup.sh` は、ユニットの `ExecStart` に `unless-stopped` が無ければ、ドロップイン `/etc/systemd/system/podman-restart.service.d/10-netconfig-manager.conf` を置いて `daemon-reload` してから有効にします（同じ内容なら書き直しません。失敗は警告して続けます）。手で行う場合は次のとおりです（`/usr/bin/podman` は `systemctl cat podman-restart.service` の `ExecStart` のパスに合わせます）

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/podman start --all --filter restart-policy=always --filter restart-policy=unless-stopped
```

  ユニットそのものが無い版では、次の内容を `/etc/systemd/system/podman-restart.service` に作ってから `sudo systemctl daemon-reload && sudo systemctl enable --now podman-restart.service` を実行します

```ini
[Unit]
Description=Start Podman containers that have restart-policy=always or unless-stopped
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/podman start --all --filter restart-policy=always --filter restart-policy=unless-stopped
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

- 手動で導入する場合（`setup.sh` を使わない場合）は、上の「前提条件」の apt-get のあと、`.env` を作って `sudo podman-compose -f docker-compose.prod.yml up -d --build` を実行します

**実機で確認する項目**（Ubuntu でしか確かめられないもの）

1. `bash scripts/check_env.sh` が `OS: Ubuntu 24.04...` を `[ OK ]` にし、NG が無いこと
2. 初回の `bash scripts/setup.sh`: apt-get で git・podman・podman-compose・netavark・aardvark-dns・uidmap が入り、ビルド・起動・起動確認・動作確認（selfcheck）まで通ること
3. コンテナ同士が名前で通信できること（`/api/health` が ok・worker が DB・Redis に届く。`sudo podman info --format '{{.Host.NetworkBackend}}'` が `netavark`）
4. 再起動後に**全コンテナ**（db・redis・backend・worker・beat・frontend）が起動すること（`podman-restart.service`。`unless-stopped` のコンテナはドロップインが無いと起動しないため要注意。`sudo systemctl cat podman-restart.service` にドロップインが出ること）
5. ufw を有効にした状態で、`setup.sh` が 80・443 を開けること（`sudo ufw status`）
6. `netconfig-backup.timer` が登録され、`sudo bash scripts/backup.sh` が成功すること（暗号化を使うなら `gnupg` の導入も）
7. 2 回目の `setup.sh`（更新）が、`.env` を変えずに最後まで通ること
8. `bash scripts/import_cert.sh` と `bash scripts/collect_logs.sh` が最後まで通ること

### 起動（本番）

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

- フロントエンドはビルド済みファイルを nginx で配信し、`/api`（WebSocket含む）を backend へ中継します
- 外部公開されるのは `HTTP_PORT`（既定 80）と `HTTPS_PORT`（既定 443）のみです。backend / DB / Redis はコンテナ内部ネットワークのみ
- HTTPS は下記「HTTPS 化」の手順で有効にしてください（ターミナルの通信に機器の操作内容が流れるため、本番では HTTPS 必須）
- Podman（podman-compose）で手動更新する場合は、イメージ再ビルド後に `podman-compose -f docker-compose.prod.yml up -d --force-recreate` でコンテナを作り直してください（podman-compose は compose ファイルが変わらないと既存コンテナを再作成しません。`setup.sh` は自動で行います）

### HTTPS 化（step-ca などで発行した証明書の取り込み）

発行済みのサーバー証明書・秘密鍵を `scripts/import_cert.sh` で取り込むと、nginx が HTTPS で配信し、HTTP は HTTPS へ転送するようになります。証明書が無いあいだは HTTP のみで動きます。

```bash
bash /opt/netconfig-manager/scripts/import_cert.sh
```

- 既定値は `setup_step-ca.sh` の出力に合わせています（Enter でそのまま採用）
  - 証明書: `~/certs/<COMMON_NAME>.crt`（中間 CA を含むチェーン。短期の `server.crt` は除外。`~` は実行ユーザー＝root のホームを先に探し、`su` した場合は元のユーザーのホームも探す）
  - 秘密鍵: 証明書と同じ名前の `.key`
  - ルート CA: `/etc/step-ca/certs/root_ca.crt`（無ければ `~/.step/certs/root_ca.crt`。`-` で指定なし）
- 取り込む前に、証明書と秘密鍵の組み合わせ・有効期限（期限切れは中止、30日以内は警告）・SAN にサーバーの IP が含まれるか・ルート CA で検証できるかを確認します
- `certs/`（Git 管理外）に `server.crt`・`server.key`（600）・`ca.crt` として配置し、`.env` の `HTTPS_PORT` とファイアウォール（firewalld。Ubuntu は ufw が有効なときだけ）を設定して nginx を再起動します。差し替え前の証明書は `/root/netconfig-manager-backup/certs-<日時>/` に退避します
- HTTPS 対応前の構成で動いている場合は、コンテナを作り直します（`setup.sh` と同じ。DB・コンフィグ履歴は保持）
- 証明書を再発行したときも、同じスクリプトをもう一度実行してください
- `.env`（`HTTPS_PORT`・`PUBLIC_URL`）を変える前に、`setup.sh` と同じ場所（`/root/netconfig-manager-backup/env-<日時>`。root のみ読める 600）へ控えを取ります。`.env` の `HTTP_PORT`・`HTTPS_PORT`・`PUBLIC_URL` は `setup.sh` と同じ読み方（前後の引用符と CR を除く）で、`HTTP_PORT="80` のように引用符が片方だけの値は不正として、何も変えずに止まります。`scripts/lib/os.sh`（`ncm_env_get`・`ncm_backup_env`）が古いままスクリプトだけ新しい場合も、`.env` に触れる前に止まります
- 証明書が読み込めない状態で起動した場合は、画面に入れなくならないよう HTTP で起動します（nginx のログに理由を出力）
- HTTP に戻す場合は `certs/server.crt`・`certs/server.key` を削除して frontend コンテナを再起動
- HTTPS で配信しているあいだは HSTS（`Strict-Transport-Security: max-age=86400`）を付けます。一度 HTTPS で開いたブラウザは、その後 1 日はこのホストへ HTTP ではなく HTTPS で接続します（詳しくは「セキュリティ」の「セキュリティヘッダー」）
  - **HTTPS にした後は HTTP に戻しにくくなります**: HTTP に戻しても、最後に開いてから 1 日のあいだは各ブラウザが HTTPS で接続しようとして開けません。期間が過ぎるのを待つか、ブラウザの設定で消してください（Chrome / Edge: `chrome://net-internals/#hsts`・`edge://net-internals/#hsts` の「Delete domain security policies」にホスト名を入力）
  - 証明書の期限が切れると、HSTS の期間中はブラウザの警告画面で「続行」できません。期限切れの前に再発行して取り込んでください（「システム状態」が期限の 30 日前・7 日前に通知します）
  - **IP アドレスで開いている場合は HSTS は効きません**（ブラウザは IP アドレスに HSTS を記録しないため）。ホスト名で開いたときだけ効きます

**利用者の PC にルート CA を登録**（初回のみ。登録しないとブラウザが証明書の警告を出します）

1. `http://<サーバー>/ca.crt` からルート CA をダウンロード（取り込み時に `ca.crt` を指定した場合のみ配布）
2. スクリプトが表示した SHA256 指紋と一致するか確認
3. Windows: 管理者の PowerShell で `Import-Certificate -FilePath .\netconfig-root-ca.crt -CertStoreLocation Cert:\LocalMachine\Root`（またはファイルをダブルクリック →「証明書のインストール」→ ローカルコンピューター →「信頼されたルート証明機関」）
4. ホスト名（例: `www.example.test`）で開く場合は、DNS か hosts ファイルにサーバーの IP を登録

### バックアップと復元

`setup.sh` が systemd タイマー（`netconfig-backup.timer`）を登録し、毎日 `scripts/backup.sh` でバックアップを取ります。

- **内容**: DB（`pg_dump`）・コンフィグ履歴（機器ごとの Git リポジトリ）・SSH の known_hosts・ターミナルの記録・`.env`・証明書（`certs/`）を1つのファイル `netconfig-backup-<日時>.tar.gz` にまとめます
- **保存先**: `/var/backups/netconfig-manager/`（root だけが読める）。`.env` の `BACKUP_DIR` で変更できます。サーバーの故障に備えて、下の「サーバー外への保管」で**サーバーの外**にも置いてください
- **保存期間**: `BACKUP_KEEP_DAYS`（既定 14 日）より古いものを削除します（最新の1つは必ず残します）
- **実行時刻**: `BACKUP_ON_CALENDAR`（systemd の OnCalendar 形式。既定 `*-*-* 03:15:00`、`off` で無効）。変更後は `setup.sh` を実行すると反映されます
- ターミナルの記録を含めない場合は `BACKUP_TERMINAL_LOGS=false`
- バックアップには `.env`（`DEVICE_ENCRYPTION_KEY`）と証明書の秘密鍵が含まれ、機器のパスワードを復号できます。持ち出すときは取り扱いに注意してください

```bash
sudo bash /opt/netconfig-manager/scripts/backup.sh          # 今すぐ実行
sudo bash /opt/netconfig-manager/scripts/backup.sh --list   # 一覧（コピー先の一覧と最後の結果も表示）
systemctl list-timers netconfig-backup.timer                # 次回の実行
journalctl -u netconfig-backup.service                      # 実行結果
```

**サーバー外への保管**（`.env` に書きます。どれもホストの `backup.sh` だけが読む設定で、コンテナには渡しません）

> **注意: バックアップには `.env`（暗号化キー `DEVICE_ENCRYPTION_KEY`）と証明書の秘密鍵が入っています。** 暗号化しないと、手に入れた人は DB の中の機器のパスワードを復号できます。外部へ置くなら `BACKUP_ENCRYPT_PASSPHRASE_FILE` で**暗号化してください**（暗号化しないで外部へ保管すると「システム状態」で注意を出します）。あわせて、コピー先は root 相当の人だけが読める場所にしてください（コピー先のディレクトリも 700。NFS は `root_squash` と export する相手の制限、SMB は専用のアカウント）。ファイルは root だけが読める（600）ままコピーします。

| 設定 | 既定 | 内容 |
|---|---|---|
| `BACKUP_COPY_DIR` | （空＝コピーしない） | NAS などを**マウントした場所**へ、作ったバックアップをコピーします |
| `BACKUP_COPY_REQUIRE_MOUNT` | `true` | コピー先が `BACKUP_DIR`・`/` と別のディスクでなければコピーしません（マウントが外れていると、マウント先のはずのディレクトリ＝サーバーのディスクへ書いてしまうため）。同じディスクの別の場所へ置くのが意図した構成なら `false` |
| `BACKUP_COPY_KEEP_DAYS` | `BACKUP_KEEP_DAYS` と同じ | コピー先の保存日数（最新の1つは必ず残します。ほかのファイルは消しません） |
| `BACKUP_POST_COMMAND` | （空） | 作成後に実行するコマンド。作ったファイルのパスは `$BACKUP_FILE`。rsync・scp・クラウドへの転送などに使います（root で実行し、1 時間で打ち切ります） |
| `BACKUP_ENCRYPT_PASSPHRASE_FILE` | （空＝暗号化しない） | パスフレーズを書いたファイル。設定すると gpg（AES256）で暗号化した `netconfig-backup-<日時>.tar.gz.gpg` を作ります（平文のアーカイブはディスクに置きません）。ファイルが無い・空ならバックアップを失敗として知らせます（暗号化しないで作ることはしません） |

```bash
# 例1: NFS をマウントしてコピー（/etc/fstab に書いて起動時にマウント）
#   nas.example.local:/volume1/netconfig  /mnt/nas-backup  nfs  defaults,_netdev  0 0
sudo mkdir -p /mnt/nas-backup && sudo chmod 700 /mnt/nas-backup && sudo mount /mnt/nas-backup
#   .env: BACKUP_COPY_DIR=/mnt/nas-backup

# 例2: rsync（SSH 鍵は root の ~/.ssh に用意し、一度手動で接続して known_hosts に登録しておく）
#   .env: BACKUP_POST_COMMAND=rsync -t "$BACKUP_FILE" backup@nas.example.local:/volume1/netconfig/

# 暗号化（パスフレーズのファイルを作り、.env に書く。gpg は AlmaLinux では gnupg2、Ubuntu では gnupg パッケージ）
sudo sh -c 'umask 077; openssl rand -base64 32 > /root/netconfig-backup.pass'
#   .env: BACKUP_ENCRYPT_PASSPHRASE_FILE=/root/netconfig-backup.pass
```

- **パスフレーズのファイルが無いと復元できません。** サーバーが壊れたときに備え、サーバーとバックアップのコピー先とは別の場所（パスワード管理ツール・金庫など）にも中身を保管してください。パスフレーズを変えたら、それ以前のバックアップには古いパスフレーズが要ります

- コピーやコマンドに失敗しても、サーバー内のバックアップは残ります（終了コード 2。systemd の状態は「failed」になります）
- 外部のバックアップから戻すときは、ファイルをサーバーへコピーして `restore.sh` に渡します（形式は同じです）
- 暗号化したバックアップ（`.gpg`）は `restore.sh` が復号します。パスフレーズは環境変数 `BACKUP_ENCRYPT_PASSPHRASE_FILE`、`.env` の同じ設定の順に探し、どちらも無ければ入力を求めます（別サーバーへの復元では、保管しておいたパスフレーズを入力します）

**結果の確認と通知**: `backup.sh` は結果を backend のコンテナ（`python -m app.tools.backup_report`）に伝えます。画面「システム状態」の「バックアップ」に最後の成功の日時・保存先・サイズ・外部コピーの結果・暗号化の有無を表示し、失敗・外部への保管の失敗・暗号化しないでの外部への保管・`BACKUP_STALE_HOURS`（既定 36 時間）以上成功していないときは「システムの異常」として通知します（下の「システム状態」）。サーバーにも `BACKUP_DIR/last-result.json` に最後の結果を残します（`--list` で表示）。

**復元**（現在のデータはすべてバックアップの時点に置き換わります）

```bash
sudo bash /opt/netconfig-manager/scripts/restore.sh /var/backups/netconfig-manager/netconfig-backup-<日時>.tar.gz
```

- アプリのコンテナを止めて DB を作り直し、コンフィグ履歴などのボリュームを入れ替えてから起動します（起動時にマイグレーションが適用されます）
- `.env` の `DEVICE_ENCRYPTION_KEY` がバックアップと違うとき（別サーバーへの復元など）は、`.env` をバックアップのものに戻します。今までの `.env` は `/root/netconfig-manager-backup/` に退避します
- **別サーバーへ移す場合**: 新しいサーバーで `setup.sh` を実行して起動したあと、バックアップファイルをコピーして `restore.sh` を実行します
- 新しいバージョンで取ったバックアップを古いバージョンに戻すことはできません（先に `setup.sh` で更新してください）


---

## 機器のグループ

デバイス管理画面で、機器をグループ（拠点・用途など）ごとにまとめて表示できます。

- 「グループの管理」でグループを作成・名前変更・削除できます（複数作成可。色と説明も設定可）
- グループの並び順は「グループの管理」の ▲▼ で変えられます。デバイス管理の表示順・各画面のグループの選択肢・Ping監視の見出しなどすべてこの順です（新しいグループは末尾に追加）
- 機器は1つのグループにだけ所属します（どこにも属さない機器は「未分類」）。所属は機器の「編集」か、「選択してグループへ移動」で複数台まとめて変更します
- 表示は「グループ別」（グループごとに見出しを付けて表示・折りたたみ可）と「一覧」を切り替えられます。グループでの絞り込みと名前・IP での検索も可能（表示の設定はブラウザに保存）
- **グループ単位の収集**: グループ別表示の見出しの「このグループを収集」で、そのグループの有効な機器をまとめて収集します（オペレーター以上）。「コンフィグ収集」画面でもグループを選ぶとその機器だけを選択します
- **グループ単位のスケジュール**: スケジュールの対象に「グループ」を選ぶと、実行時点でそのグループに所属する有効な機器を収集します（機器を追加・移動してもスケジュールの変更は不要）
- **絞り込み**: 世代管理（機器の選択肢をグループごとに表示）・コンプライアンス（違反一覧・機器別）・構成図の「未配置の機器」でグループを指定して絞り込めます
- グループを削除しても機器は削除されず、未分類に戻ります（そのグループを対象にしたスケジュールは無効になります）
- グループの作成・変更と所属の変更は、機器の登録と同じく管理者の権限が必要です

## 機器の CSV 一括登録

デバイス管理の「CSV 取り込み」で、CSV ファイルから複数の機器をまとめて登録できます（管理者のみ。機器の登録と同じ権限）。

> **注意: CSV にはパスワードがそのまま（平文で）書かれます。** 取り込みが終わったら、ファイルをパソコン（ダウンロードフォルダ・ごみ箱を含む）や共有フォルダから必ず削除してください。メールやチャットで送らないでください。サーバーはファイルを保存せず、メモリの上で読むだけです。結果の画面・エラーメッセージ・監査ログ・サーバーのログにパスワードは出しません。

- **流れ**: 「ひな形をダウンロード」→ 記入 →「ファイルを選ぶ」→「内容を確認」（登録はせず、行ごとの結果とエラーを表示）→「○台を登録する」。登録のときにもサーバーで検証し直します
- **列**（1 行目は見出し。順番は自由。英語の見出し `name`・`hostname`・`platform`・`username`・`password` なども可）

  | 列 | 必須 | 内容 |
  |---|---|---|
  | 名前 | ✓ | 機器の識別名（最大 128 文字） |
  | ホスト / IP | ✓ | IP アドレスかホスト名（全角の英数字は半角に直して読みます） |
  | 機種 | ✓ | 機種の ID（`cisco_ios` など）か表示名（`Cisco IOS` など。デバイス追加画面の選択肢と同じ）。大文字小文字・全角半角の違いは問いません |
  | ユーザー名 | ✓ | SSH のユーザー名（認証情報プロファイルを指定した行は空） |
  | パスワード | ✓ | SSH のパスワード（前後の空白もそのまま使います。認証情報プロファイルを指定した行は空） |
  | ポート | | 空なら 22 |
  | グループ | | 登録済みのグループの**名前**（無い名前はエラー。自動では作りません） |
  | 踏み台 | | 登録済みの踏み台サーバの**名前** |
  | 認証情報プロファイル | | 登録済みの認証情報プロファイルの**名前**。指定した行はユーザー名・パスワードを空にできます（書いてあっても使わず、警告を出します） |
  | 有効 | | 「はい」「いいえ」（空なら有効） |
  | Enable パスワード | | Cisco などの enable 用 |
  | 応答待ち時間（秒） | | 10〜600（空なら既定値） |
  | 説明 | | 最大 1000 文字 |
- **台帳 CSV との関係**: 見出しは「台帳 CSV」（書き出し）とそろえてあり、台帳 CSV に「ユーザー名」「パスワード」の列を足して埋めれば取り込めます（「認証情報プロファイル」の列も台帳 CSV と共通です。プロファイルを使う行はユーザー名・パスワードを空のままにできますが、列の見出しは必要です）。台帳だけの列（モデル・シリアル番号など）は読み飛ばします。台帳 CSV は認証情報を書き出さないため、そのままでは取り込めません
- **SSH 鍵は CSV では登録できません**（パスワードが空の行はエラー）。鍵で接続する機器は、鍵を入れた認証情報プロファイルを指定するか、1 台ずつ登録してください
- **エラーのある行**: 既定では 1 行でもエラーがあれば何も登録しません。「エラーのない行だけ登録する」を選ぶと、正しい行だけ登録します
- **同じ名前の機器**: 既に同じ名前の機器がある行は「スキップする」（既定。同じファイルを何度取り込んでも同じ結果になります）か「エラーにする」を選べます。既存の機器を CSV で上書き（更新）はしません。ファイルの中での名前の重複はエラー、大文字小文字だけ違う名前・同じ IP の機器は警告だけで登録します
- **文字コード**: UTF-8（BOM あり・なし）と Shift_JIS（Excel の「CSV（コンマ区切り）」）を自動で判別します。UTF-16（Unicode テキスト）は読めません。区切りはコンマのみ
- **上限**: 1 回に 500 行・1MB まで。`#` で始まる行と空行は読み飛ばします（名前が `#` で始まる機器は登録できません）
- **Excel で編集するとき**: 数字だけ・先頭が 0 のパスワード（`00123` など）や、`=` `+` `-` `@` で始まる値は Excel が書き換えることがあります。メモ帳などで編集するか、列の書式を「文字列」にしてから入力してください（台帳 CSV が値の先頭に付ける `'` は、名前・説明に限り取り込むときに外します）
- 登録しただけではコンフィグは収集しません（「一括収集」やスケジュールで収集します）
- **監査ログ**: 取り込み 1 回ごとに「機器の CSV 一括登録」（件数だけ）と、機器ごとの「機器登録」（`via: csv`）を記録します。内容の確認だけでは記録しません

## 機器への SSH 認証

機器ごとにパスワード・SSH 秘密鍵のどちらか、または両方を設定できます（直接接続・踏み台経由のどちらでも使えます）。

- 秘密鍵は OpenSSH 形式（`-----BEGIN OPENSSH PRIVATE KEY-----`）または PEM 形式の RSA / ECDSA / Ed25519。パスフレーズ付きの鍵も使えます
- 両方を設定した場合は鍵 → パスワードの順に試します
- 秘密鍵・パスフレーズは暗号化して保存し、画面・API には鍵の種類と指紋のみ表示します
- Cisco 等で enable が必要な場合は、鍵認証でも「Enableシークレット」を設定してください

## 認証情報プロファイル

同じアカウント（ユーザー名・パスワード・Enable・SSH 鍵）を使う機器が多いときは、「認証情報プロファイル」画面でプロファイルを 1 つ作り、デバイスの編集で「プロファイルを使う」を選びます。パスワードを変えるときはプロファイルを 1 か所直すだけで、それを使う全機器の**次の接続**（コンフィグ収集・SSH ターミナル・FW ヒット数）から反映されます（実行中の収集は開始時の値のまま）。

- プロファイルを選んだ機器は、機器側の認証情報を一切使いません（項目ごとの上書きはしません）。保存したとき、その機器に入っていたユーザー名・パスワード・鍵・Enable は消します（古い値を残さないため）
- プロファイルを外して「この機器だけの認証情報を入力する」に戻すときは、ユーザー名と、パスワードまたは SSH 秘密鍵の入力が必要です
- 接続に使う認証情報は 1 か所（`backend/app/services/connection.py` の `effective_credentials`）で決めます。デバイス管理のカードの「🔑 鍵認証」などの表示も同じ値から出します。カードには「🪪 認証: プロファイル名」を表示します
- 秘密の値は機器と同じく `DEVICE_ENCRYPTION_KEY` で暗号化して保存し、API・画面には有無と鍵の種類・指紋だけを返します。監査ログにも値は残さず「（変更）」とだけ記録します（プロファイルの変更には、影響する機器の台数も残します）
- 使用中のプロファイルは削除できません（使っている台数を表示します）。機器の削除には影響しません
- 一覧は機器を閲覧できる人なら見られます（名前・ユーザー名・有無のみ）。登録は機器の登録と同じく管理者のみです

### 所有者と共有範囲（だれが編集・使用できるか）

プロファイルは、登録した人が**所有者**になります。管理者であっても、ほかの人のプロファイルを勝手に編集・削除・割り当てすることはできません。ほかの人と共有するときは、所有者がプロファイルの編集画面でユーザーグループ（「通知設定」で作るグループ）を選びます。

| できること | 所有者 | 「管理」のグループ | 「使用」のグループ | それ以外の管理者 |
|---|:-:|:-:|:-:|:-:|
| 一覧で見る（値は表示されません） | ✓ | ✓ | ✓ | ✓ |
| 編集・削除・共有範囲の変更・所有者の変更 | ✓ | ✓ | | |
| 機器への割り当て（1 台ずつ・CSV 一括登録） | ✓ | ✓ | ✓ | |
| このプロファイルを使う機器の接続先（IP アドレス・ポート・踏み台）の変更 | ✓ | ✓ | ✓ | |
| 引き継ぐ（所有者を自分にする） | | ✓ | ✓ | ✓ |

- 何も選ばなければ、所有者だけが編集・使用できます
- **接続先の変更も「使用」に含めています。** 接続先を別のサーバーに書き換えると、次の接続でプロファイルのパスワードがそこへ送られるためです。プロファイルを外して自分で認証情報を入力する変更は、機器を編集できる人なら行えます
- コンフィグ収集と SSH ターミナルは、共有範囲に関係なく今までどおり行えます（オペレーターも可。パスワードそのものは誰にも表示されません）
- **引き継ぐ**: 所有者が不在・退職などで誰も編集できないとき、管理者が所有者を自分に変えられます。監査ログ（認証情報プロファイルの引き継ぎ）に残り、前の所有者へ通知します。共有範囲はそのまま残ります。所有者のユーザーを削除すると「所有者なし」になり、引き継ぐまで「管理」のグループだけが編集できます
- **所有者への通知**: ほかの人が編集・削除・引き継ぎ・機器への割り当て・接続先の変更をすると、所有者の通知先（「通知設定」の自分の設定。グループの設定を引き継いでいる場合はそのグループ）へ知らせます。通知する内容の選択に関係なく送ります
- この制限は、誤操作の防止と責任の明確化のためのものです。管理者はユーザーのパスワードをリセットできるなど強い権限を持つため、悪意のある管理者まで防ぐものではありません（引き継ぎ・変更は監査ログと通知で追跡できます）
- 以前のバージョンで作ったプロファイルの所有者は、更新時に `admin`（いなければ最初に作られた管理者）になります
- 機器台帳の CSV に「認証情報プロファイル」の列（名前のみ）があり、CSV 一括登録でもプロファイル名を指定できます
- 踏み台サーバには今は使えません（踏み台は従来どおり踏み台ごとに認証情報を設定します）

## 応答の遅い機器（応答待ち時間）

PAN-OS などログイン後のプロンプト表示やコマンド応答に時間のかかる機器向けに、応答待ち時間（秒）を調整できます。

- 既定値は `.env` の `SSH_READ_TIMEOUT`（既定 120 秒、10〜600）
- 機器ごとにデバイス設定の「応答待ち時間」で上書きできます（空欄で既定値）
- PAN-OS は常に、それ以外の機器は個別に指定した場合に、ログイン直後のプロンプト待ちを含むすべての待ちにこの値を適用します（Netmiko 既定の 10〜20 秒固定の待ちを上書き）
- 待ち時間は上限です。応答が来ればすぐ次の処理へ進むため、長めに設定しても通常の収集時間は変わりません
- タイムアウトした場合は収集ログに「機器の応答待ちがタイムアウトしました」と表示されます

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

## 構成図

「構成図」画面で、登録済みの機器を配置して線で結んだ簡易的な構成図を作れます。

- 構成図は複数作成できます（拠点・フロア・用途ごとなど）。複製・名前変更・削除も可能
- 1つの構成図に「物理構成」と「論理構成」の2枚のキャンバスがあり、上部のタブで切り替えます（配置・線はそれぞれ別に保存。同じ機器を両方に置けます）
- 論理構成の編集中は「物理構成からコピー」で、保存済みの物理構成の機器を同じ位置に配置できます（非管理機器・雲を含めるか、配置済みの機器も物理構成の位置へ動かすか、機器どうしの接続線もコピーするかを選択。図形・テキスト・グループ枠はコピーしません）
- 機器は右の「未配置の機器」からドラッグして配置します（1つの構成図に同じ機器は1回まで。別の構成図には何度でも置けます）
- 登録していない機器（ISPルーター・ハブ・PC など）は「＋ 非管理機器」で置けます。名前・補足（IP・型番など）・アイコンを自由に設定でき、破線の枠で表示します（収集・ターミナルの対象外）
- 機器の縁の ● から別の機器（非管理機器・雲を含む）へドラッグすると線を引けます。相手の箱の上ならどこで離してもつながります。線には両端のポート名・ラベル・線の種類（実線/破線）・色を設定できます。同じ2台の間に複数本引くと平行線で表示します
- 装飾として「雲」「テキスト」「グループ枠」を置けます（色・文字・大きさを変更可能）。グループ枠はラベル部分をドラッグして移動し、そのとき枠の中にある機器・図形なども一緒に動きます（中心が枠の内側にあるもの。Alt を押しながらドラッグすると枠だけ動かせます）
- 機器アイコンは最後の収集結果で色分けされます（緑: 成功 / 黄: 変更あり / 赤: 失敗 / 灰: 未収集）。状態は30秒ごとに自動更新
- 機器をクリックすると、ターミナル・変更履歴・今すぐ収集へ移動できます（ロールの権限に応じて表示）
- 論理構成では、自由に作図するための要素を追加できます
  - 図形（四角・角丸・楕円・ひし形）: 文字・塗り・枠線（実線/破線/点線）を設定。OSPF エリアや DMZ などの範囲を囲むのに使います
  - セグメント: VLAN・サブネットを表す線（横長・縦長）。線をつなぐとセグメント上に垂直に落ちます
  - 中継点: 線を折り曲げたり分岐させたりするための点
- 線は、物理・論理どちらでも矢印（片側/両側）・経路（直線/カギ線/曲線）・太さ・線種（実線/破線/点線）を設定できます
- 機器には補足（例: `Lo0 10.255.0.1`）を書けます。機器の下に表示されます
- 「書き出し」で表示中の構成（物理/論理）全体を出力できます
  - PNG（画面の配色）/ PNG（白背景）/ PDF（A3、図の縦横に合わせて用紙の向きを選択、題名と出力日時入り）/ 印刷（別ウィンドウで印刷ダイアログを開く。「PDF に保存」も可）
  - 白背景は画面の配色を反転して作ります（機器・線の色味は保ちます）
  - ファイル名は「構成図の名前_物理構成（または論理構成）」です。PNG（白背景）は末尾に `_白背景` が付き、画面の配色の PNG と区別できます（例: `本社ネットワーク_物理構成_白背景.png`）
  - PDF のライブラリ（jsPDF）は書き出すときだけ読み込みます
- 編集は「編集」ボタンで開始し、「保存」で確定します。他のユーザーが先に保存していた場合は上書きせずにエラーになります（再読み込みしてから編集し直してください）
- 編集中は ↶（取り消す・Ctrl+Z）/ ↷（やり直す・Ctrl+Shift+Z / Ctrl+Y）で操作を戻せます（移動・追加・削除・線の接続・大きさや設定の変更。同じ項目への続けての入力は1回分にまとめます。最大100回）。保存しても履歴は残るため、保存より前の状態にも戻せます（保存した状態から離れると「未保存」になります）。「変更を破棄」・変更を破棄しての編集の終了・別の構成図への切り替え・再読み込みで履歴はリセットされます。文字の入力欄では、その欄の取り消しが優先されます
- 機器を削除すると、その機器は構成図からも取り除かれます（つながっていた線も削除）

## コンプライアンスチェック

「コンプライアンス」画面で検査ルールを登録すると、収集したコンフィグを自動で検査し、違反を一覧表示します。

- ルールは「一致する行が必要 / あってはいけない」×「文字列を含む / 正規表現」で、1行ずつ判定します
- 範囲は「コンフィグ全体」か「セクションごと」。セクションは行頭に空白の無い行を見出し、続く字下げされた行を中身とします（例: 見出し `^interface GigabitEthernet` の各セクションに `description` が必要）
- 対象のプラットフォームを絞れます（未選択なら全機種）。重要度は高・中・低
- 検査のタイミング: 収集に成功したとき（その機器）、ルールを作成・変更したとき・「全機器を再検査」を押したとき（全機器）、種類「コンプライアンスチェック」のスケジュール（下記）
- **定期的な検査**: 「スケジュール設定」で種類に「コンプライアンスチェック」を選ぶと、機器には接続せず、収集済みの最新のコンフィグを Cron 式の時刻に検査し直します（対象は全機器・グループ・機器を選べます）。収集の頻度が低い機器の再確認や、期限切れになった例外の反映に使います。結果（検査した台数・新しい違反・解消の件数）はアクティビティログに残ります
- ルール編集画面の「試す」で、保存前に機器の最新のコンフィグで判定結果を確認できます（オペレーター以上）
- 正規表現の照合は 1回の評価（ルール × 機器）あたり `COMPLIANCE_REGEX_TIMEOUT` 秒（既定 2 秒）で打ち切り、結果は「エラー」になります。`(…+)+` のような量指定子の入れ子など、照合に時間のかかるパターンは避けてください
- 再検査（ルールの保存・例外の登録・削除・「全機器を再検査」）の照合は専用のスレッドで行うので、機器やルールが多くても、その間にほかの利用者の操作が止まることはありません。同時に照合するスレッドは `COMPLIANCE_CHECK_CONCURRENCY` 個（既定 2、API と worker のプロセスごと）までで、超えた分は順番を待ちます。照合を先に全部済ませてから結果の書き換え（削除と保存）を最後に短く行うので、途中で切れても以前の結果が残ります。照合の間に消された機器・ルール、変更されたルールの分は書き込みません（変更したルールの結果は、変更を保存した側の再検査が書きます。例外の変更は検知しないので、その保存で走る再検査が書き直します）。PostgreSQL ではアドバイザリロックで書き換えを直列にし、書き込みの直前に機器・ルールの行をロックして、再検査が同時に走っても一意制約・外部キーに当たりません。機器・ルールの削除も同じロックを先に取るので、再検査と重なってもデッドロックになりません（照合した時点より新しい結果を古い結果で上書きすることはありえますが、次の再検査で直ります）
- **違反の通知は、保存（commit）が成功したあとに投入します**: `run_checks` は通知を投入待ちとしてセッションに積むだけで、呼び出し側（API・worker）が commit したあと（SQLAlchemy の `after_commit`）に Celery へ投入します。commit に失敗・rollback したときは捨てるので、保存されなかった違反は通知されません（次の再検査で「新しい違反」として通知されます）。アドバイザリロックを持っている間は Redis と通信しません
- 正規表現（ルール・セクションの見出し・例外の箇所）は、保存・「試す」の前に実際に読み込んで重さを測り、重いものは理由付きで受け付けません（422。「セキュリティ」の「利用者が入力する正規表現の制限」）。重いルールが DB に入っていても、検査の実行時にはそのルールだけ「エラー」にします（検査全体は止めません）。読み込めない例外の箇所は使わず（違反のまま）、ログに残します
- 「テンプレートから追加」で、よく使う基準（SSH v2・Telnet 禁止・HTTP サーバー無効・SNMP コミュニティ・NTP、FortiGate の管理アクセス、AlliedWare Plus の Telnet / HTTP 無効化など）をまとめて登録できます
- 違反のある機器は構成図にも ⚠ と件数を表示します（色は最も重い違反の重要度）
- **例外（承認済みの逸脱）**: 違反一覧の「例外にする」、またはルール一覧の「例外」から登録します。例外で外れた結果は「除外」となり、違反の件数・構成図の ⚠ に数えません
  - 機器単位: その機器ではルールの違反をすべて除外（機器の更改待ちなど）
  - 該当箇所単位: 正規表現に一致する箇所だけを検査から外します。セクションごとのルールは**見出し**（例: 予備ポート `^interface GigabitEthernet1/0/2$`）、コンフィグ全体で「あってはいけない」ルールは**違反の行**に一致させます。違反箇所から正規表現を作るボタンがあります。対象を「全機器」にもできます（このときは箇所の指定が必要）
  - コンフィグ全体に「必要」なルールは外す箇所が無いため、機器単位のみ使えます
  - 理由は必須、期限は任意（その日の終わりまで有効）。期限が切れると例外は使われなくなり、5分以内に自動で対象を再検査します（違反に戻ったことと期限切れはアクティビティログに残ります）。「例外」タブには「期限切れ」と表示します
  - 登録・削除すると対象をすぐ再検査します。登録・削除は監査ログに、違反が除外になったことはアクティビティログに残ります
- 閲覧は閲覧者以上、ルールの編集・例外の登録・再検査はオペレーター以上

## Ping監視

「Ping監視」画面で、登録済みの機器と指定した IP アドレス / ホスト名に一定間隔で PING し、応答状況をリアルタイムに表示します（deadman 風。「リアルタイム」タブ）。画面を開いていなくても見張りたい対象は「常時監視」タブに加えます（下の「常時監視」）。

- **対象**: 登録機器（デバイス設定の「ホスト」のアドレス）と、「IP を追加・管理」で登録した IP / ホスト名（ゲートウェイ・DNS・サーバーなど機器以外の宛先）
- **表示**: 機器のグループごとに、状態・損失率・送信/受信数・最新/平均/最小/最大の応答時間・最終応答からの経過時間・直近60回の履歴（棒の高さ＝応答時間、赤＝応答なし）。応答なしの行は赤く点滅します
- 「対象を選ぶ」でグループ単位・個別に監視対象を選べます（選択と間隔はブラウザに保存）。間隔は 1 / 2 / 5 / 10 秒
- 「異常のみ表示」で、応答なし・損失あり・名前解決失敗の対象だけを表示
- 統計は画面で集計しており、画面を離れる・「統計リセット」でリセットされます（記録と通知は「常時監視」で行います）
- PING は**サーバーから**送信します。踏み台の先にある機器など、サーバーから直接届かない宛先は「応答なし」になります
- 画面からは登録済みの対象しか指定できません（任意のアドレスへの PING にサーバーを使わせないため、アドレスはサーバー側で引き当てます）
- ICMP の送信には backend・worker コンテナに `NET_RAW` 権限と `net.ipv4.ping_group_range` の設定が必要です（docker-compose に設定済み）
- `.env` の `PING_TIMEOUT`（1回の応答待ち、既定 1 秒）・`PING_MAX_TARGETS`（同時に監視できる対象数、既定 300）で調整できます
- 利用は閲覧者以上、IP の追加・編集・削除はオペレーター以上。追加・変更・削除は監査ログに残ります

### 常時監視

画面を開いていなくても、worker が `PING_MONITOR_INTERVAL_SEC` 秒（既定 60 秒）ごとに PING し、結果を残して、応答しなくなったことを通知します。

- **対象**: 「常時監視」タブで、登録機器・追加 IP から選んで「加える」（オペレーター以上。監査ログに残ります）。最大 `PING_MAX_TARGETS` 件。無効の機器は PING しません。「やめる」で外すと、その対象の記録も削除します。機器・追加 IP を削除すると常時監視からも外れます
- **状態**: 応答あり（続けて応答が無かった回数も表示）/ 応答なし（いつから）/ 未確認。最後の応答時間・最後に確認した時刻・直近 24 時間の応答率を一覧に表示します（15 秒ごとに更新）
- **推移**: 「推移」で、1 時間〜14 日の応答時間の平均（線）と応答なし（下の帯。赤が濃いほどその時間の応答なしが多い）をグラフで表示します。グラフにマウスを載せると、その時間の平均・最大・回数を表示します
- **応答なしの判定と通知**: `PING_ALERT_AFTER` 回（既定 3 回）続けて応答が無い（名前解決できない場合も含む）と「応答なし」、その後 1 回でも応答すれば「復旧」です。どちらもアクティビティ（Ping監視）に残り、通知設定で「Ping監視」を選んだ通知先へ送ります。1 回の実行で応答なし・復旧になったものは、通知先ごとに 1 通にまとめます（ネットワーク障害で多数が同時に落ちても通知があふれないように）。応答なしが続いている間は繰り返し通知しません
  - この項目を追加する前からある通知設定は、「システムの異常」を選んでいるものだけ有効になります
- **記録**: 1 回の PING ごとの結果を `PING_HISTORY_DAYS` 日（既定 14 日）残し、毎日の古いログの削除で消します。対象 300 件・60 秒ごとなら 1 日約 43 万行です
- 判定に使う状態（続けて応答が無かった回数など）は Redis に持ちます。Redis を作り直すと状態は「未確認」から始まります
- 前の実行が終わっていないときは、その回を飛ばします（PING の応答待ちは間隔の 4 分の 1 以下に抑えます）

## モニタリング（試験導入）

インタフェースの帯域の使用率と、FW のルール（ポリシー）のヒット数を確認する画面です。**試験導入のため既定では無効**で、メニュー（「監視」）にも表示されません。運用で問題がないことを確かめたうえで、既定を有効に切り替える予定です。

### 有効にする

1. `.env` に `MONITORING_ENABLED=true` を追加する（`.env.example` 参照）
2. `bash scripts/setup.sh` でコンテナを作り直す（メニュー「監視」に「モニタリング」が表示されます）
3. 「モニタリング」→「SNMP 設定」で、帯域を見たい機器ごとに SNMP を設定する

無効に戻すときは `MONITORING_ENABLED=false` にしてコンテナを作り直します。記録したデータは残り、再度有効にすると続きから使えます（不要なら機器ごとに「SNMP 設定」から削除）。

### インタフェース（帯域の使用率）

- SNMP（IF-MIB の 64bit カウンタ `ifHCInOctets` / `ifHCOutOctets`、速度は `ifHighSpeed`）で `MONITOR_INTERVAL_SEC`（既定 5 分）ごとに取得し、前回との差から bps と使用率を計算します（**2回目の取得から**値が出ます）
- 一覧: 使用率の高いインタフェース（全機器）、または機器ごとのインタフェース（名前・説明・状態・速度・入力/出力の bps と使用率）。使用率 50% 以上は黄、80% 以上は赤
- 行を選ぶと推移のグラフ（1時間〜30日）。長い期間はきりのよい間隔（30分など）の平均で表示し、ツールチップに区間の最大値を出します。取得できなかった時間は線を切ります
- 前回の取得から取得間隔の半分未満しか経っていない読み取り（「今すぐ取得」の直後など）は誤差が大きいため記録しません
- 記録は稼働中（up）のインタフェースだけ、`MONITOR_RETENTION_DAYS`（既定 30 日）保存します（1,000 インタフェースで約 860 万行が目安）
- SNMP v2c（コミュニティ名）と v3（認証 SHA / SHA-256 / MD5・暗号化 AES-128 / AES-256 / DES）に対応。コミュニティ名・パスワードは `DEVICE_ENCRYPTION_KEY` で暗号化して保存します
- SNMP は**サーバーから機器へ UDP 161 で直接**届く必要があります（踏み台経由の機器は不可）。機器側で SNMP を有効にし、サーバーのアドレスからの読み取りを許可してください
- 「保存して接続確認」で sysName / sysDescr を取得して疎通を確認できます。「今すぐ取得」で次の定期取得を待たずに取得します

### FW ルール（ヒット数）

- 対象: Palo Alto（PAN-OS）・Fortinet（FortiGate）として登録した機器。コンフィグ収集と同じ認証情報で SSH ログインし、`MONITOR_FW_INTERVAL_MIN`（既定 60 分）ごとに取得します（踏み台経由も可）。同じ機器のコンフィグ収集とは重ならないようにしており、収集中ならその回は取得しません（FortiGate は接続のたびに console の設定を変えて戻すため、重なると出力が止まるため）
  - PAN-OS: `show rule-hit-count vsys vsys-name <MONITOR_PANOS_VSYS> rule-base security rules all`
  - FortiGate: `show firewall policy`（ID と名前）と `diagnose firewall iprope list 100004`（ヒット数・パケット・バイト・初回/最終ヒット）
- FortiGate の console の設定（推奨: `standard`）: Netmiko はページングを止めるため、接続のたびに `config system console` の `output` が `more` なら `standard` に変え、切断時に `more` へ戻します。ヒット数は定期的（既定 60 分ごと）に取得するので、そのたびに FortiGate のイベントログ（システムの設定変更）に記録が残ります。FortiGate 側で次のように `standard` にしておくと、変更も戻しも行われず記録も残りません（収集用アカウントに設定の書き込み権限も不要になります）。コンフィグ収集についても同じです
  ```
  config system console
      set output standard
  end
  ```
- 表示: ルールの順・名前・ヒット数・前回の取得からの増加・最終/初回ヒット（FortiGate はパケット/バイトも）。日時は機器の出力どおり（機器のローカル時刻を `TIMEZONE` の時刻とみなします。epoch 秒で出力された日時も `TIMEZONE` の時刻に直します）。**一度もヒットしていない、または最終ヒットが 30 日以上前**のルールに「未使用」の印を付け、絞り込めます（ルールの棚卸し用）
- 取得に失敗したときは前回の結果（ルールの一覧）を残したままエラーを表示し、アクティビティに「FW ヒット数の取得失敗」を記録します。「取得した出力」は今回の出力です（接続できず出力が無い失敗では、古い出力を表示しないよう消します）。FortiGate で `diagnose firewall iprope list` の統計を読めない（権限不足・VDOM 構成など）ときも、全ポリシーを「未使用」とせずに失敗として扱います
- 機種や OS のバージョンで出力が違い正しく読めない場合は、「取得した出力」（管理者）で機器の出力を確認できます。試験導入中に合わない出力があれば、その内容をもとに読み取りを調整します
- 現時点の制限: FortiGate の VDOM（複数 VDOM 構成）、PAN-OS の複数 vsys の同時取得、Panorama 経由の取得には対応していません

### 権限

- 閲覧（インタフェース・FW ルール）: 閲覧者以上
- 「今すぐ取得」: オペレーター以上
- SNMP の設定・削除・接続確認、「取得した出力」の表示: 管理者（機器の登録・編集と同じ権限）
- SNMP 設定の変更・削除、FW ヒット数の手動取得は監査ログに残ります

## 脆弱性とサポート期限（ファームウェアの管理）

機器の OS バージョン（機器台帳の `os_version`）を、公開されている **脆弱性情報** と **サポート終了日** に照合して、該当する機器を一覧にします。**既定は無効**（`VULN_ENABLED=false`）で、無効のあいだはメニューにも出ず、サーバーは外部へ一切つながりません。

### 何を・どこから取るか

| 情報 | 取得元（HTTPS） | 使い方 |
|---|---|---|
| Palo Alto（PAN-OS）の脆弱性の勧告 | `security.paloaltonetworks.com`（公式の Security Advisories API。`/api/v1/products/PAN-OS/advisories`＝製品の全勧告） | 勧告ごとの影響範囲（リリース系列ごとの「この版より前」）と、機器の OS バージョンを照合 |
| 悪用確認済みの印 | `www.cisa.gov`（Known Exploited Vulnerabilities Catalog の JSON） | 勧告の CVE が載っていれば「悪用確認済み」（対応の期限つき） |
| サポート終了日（OS） | `endoflife.date`（PAN-OS・FortiOS・Cisco IOS XE のリリース系列ごと） | 機器の OS のリリース系列（10.2 など）の終了日と残り日数 |
| サポート終了日（手入力） | 画面から入力（OS の系列ごと・ハードウェアのモデルごと） | 優先順位は **特定の系列の手入力 → 特定の系列の自動取得 → 系列 `*`（その機種のすべて）の手入力**（`*` は「系列の終了日が分からないときの既定」で、自動取得の特定の系列の日付より後に引きます）。ハードウェア（モデル単位）は別枠で、手入力を引きます。機器の platform と分解したリリース系列で引くので、Junos・NX-OS・ASA・EOS・IOS など台帳が読める全機種で使える。バージョンを分解できない機種（AlliedWare Plus・Yamaha など）は、系列に `*` かモデル単位で登録する。`cisco_ios` として登録された IOS XE（17.x）は、特定の系列の手入力・自動取得を `cisco_ios` でも `cisco_xe` でも引く（`*` の手入力は機器そのものの platform のものだけ。classic IOS 向けの `cisco_ios` の `*` は、`cisco_xe` の機器に当たりません） |

- **対応している機種**: 脆弱性の照合は **PAN-OS（Palo Alto）だけ**です。サポート終了日は PAN-OS・FortiOS・Cisco IOS XE が自動取得で、ほかの機種は手入力で登録します。Fortinet・Cisco・Juniper・Arista などの脆弱性の照合は今後の拡張です（「今後の拡張ポイント」）。バージョンの読み取りは FortiOS・Cisco IOS XE / IOS / NX-OS / ASA・Junos・EOS にも対応しています（サポート終了日の系列を引くため）
- **外部へ送らないもの**: 機器名・IP アドレス・OS バージョン・モデルなど、機器の情報は一切送りません。取得は製品単位（「PAN-OS の勧告すべて」）で、URL にクエリも付けません。どの機器が該当するかの照合は、サーバーの中で行います
- **「該当」の意味と限界**: 「該当」は、ベンダーの勧告の影響範囲と OS バージョンを照合した結果です。**特定の機能を使っているか・設定がどうなっているかは見ません**（該当と出ても影響を受けない構成はありえます）。逆に、**載っていない脆弱性がありえます**（勧告の公開の遅れ・取得の失敗・対象外の機種・読み取れない OS バージョン）。見つからないことは、安全を意味しません。ベンダーの公式の案内を併せて確認してください
- バージョンが読み取れない機器・対象外の機種は、誤って「該当」「非該当」にせず、画面の「判定できない機器」に理由つきで出します（読み取れる書き方は `backend/app/services/vuln_match.py` の先頭に表で書いています）
- **影響範囲の照合の規則**（PAN-OS。Palo Alto の API の CVE JSON 5.0 の `affected` を、2026-11 に本物の応答と勧告のページの表で確かめて決めたもの。`backend/app/services/vuln_match.py` の `_span`・`judge_detail`）。影響範囲は同じリリース系列（`x.y`）の中で比べます。行（`versions[]` の 1 件）ごとに:
  1. 範囲の始まりは `version`（`12.2` は `12.2.0` として読む）。`version` より前は非該当
  2. 修正点は `changes` の `at`（status が unaffected）と `lessThan` の両方です。**`lessThan` は修正点の最大のことも最小のこともある**ので、`lessThan` で範囲を打ち切りません（例: `lessThan: 12.1.4-h7`、`changes: 12.1.4-h7・12.1.7` の行では、`12.1.5`・`12.1.6-h1` も該当）
  3. 機器の版 `x.y.z-hN` は、同じ保守版 `x.y.z` に修正点 `x.y.z-hM` があれば N ≧ M で非該当・N ＜ M で該当。同じ保守版に修正点が無ければ、**最大の修正点より前なら該当・以上なら非該当**。例: 修正点が `10.2.7-h40`・`10.2.10-h43`・`10.2.13-h28`・`10.2.16-h13`・`10.2.18-h14` のとき、`10.2.13-h28`・`10.2.7-h40`・`10.2.18-h14`・`10.2.19` は非該当、`10.2.13-h27`・`10.2.7`・`10.2.14`・`10.2.17`・`10.2.18-h13` は該当。修正点の並び（昇順・降順・順不同）には頼りません
  4. `version` だけの行（`lessThan`・`changes` が無い）は、**その系列の `version` 以上すべて**（修正版が無い系列。勧告の表では「10.2: All」）。影響なし（`status: unaffected`）の `version` だけの行、製品名が `PAN-OS 11.1` のような系列つきで `version: All` の行は、その系列が影響なし
     - **2024 年 10 月ごろより前の古い形**は、表の言葉をそのまま `version` に入れています。`"9.0 All"` は「その系列すべてが行の status」（affected なら該当、unaffected なら非該当）、`"9.1 None"` は「この列に当てはまる版は無い」の意味で、判定には使いません（系列が表に載っていることだけ数えます）。例: `"9.1 All"` 影響あり＋`"9.1 None"` 影響なし → 9.1 はすべて該当。逆の組 → すべて非該当
     - `version: " All"`（先頭の空白は無視）は製品全体（すべての系列）
  5. 製品の `defaultStatus` が `affected` で、機器の版が同じ製品行の読める行で決まらなければ、非該当にせず **「候補」**（注記「勧告は、記載のない系列も影響ありとしています」）。`unknown` などなら「判定できない」。`unaffected`・無しなら非該当。「決まらない」は、系列がどの行にも無いとき、または版がその系列の読める行の**始まり（version）より前**か **lessThanOrEqual より後**のときです。**changes の修正点（at）以上は、既定にかかわらず非該当**です（changes の at は「ここから影響なし」という行の明記。例: CVE-2026-0279 の形は defaultStatus が affected で、`lessThan 12.1.8`・`changes [12.1.8]`、表は「12.1 は 12.1.8 以上が影響なし」）。**changes に無い lessThan** は「この版より前が影響あり」と言うだけなので、lessThan 以上の版は、始まりより前・lessThanOrEqual より後と同じく既定に従います（changes に lessThan と同じ at がある本物の形は、changes の根拠で非該当）。例: defaultStatus が affected で `version 10.2.5, lessThan 10.2.9`（changes なし）の行だけ → 10.2.1・10.2.12 は候補。同じ行に `changes [10.2.9]` があれば 10.2.12 は非該当。defaultStatus が unaffected・無しなら、lessThan 以上は今までどおり非該当
  5-2. `platforms` が付いていて **Panorama だけではない行**（例: `["PA-3200", "PA-5200", "PA-7000"]`）は、機種を自動では決めず **「候補」**（注記「特定の機種だけに影響する勧告です（対象: PA-3200, PA-5200, PA-7000）。機種を確かめてください」）。Panorama と判別できた機器には、platforms に Panorama と読める要素（`Panorama`・`Panorama M-Series` など）があれば当て、**すべての要素の全体がファイアウォールの機種名（`PA-数字…`・`PA-VM`・`VM-数字…`。後ろの ` Series` は可。例 `PA-3200 Series`）と一致するときだけ**当てません（`PA-VM / M-600` のような表記は候補）。ファイアウォールの機器を「Panorama だけ」として当てないのは、すべての要素の全体が `Panorama`（大文字小文字・前後の空白は無視）と一致するときだけです（`Firewalls managed by Panorama` は候補）。`["All"]`・`["PA-Series", "VM-Series"]` のように Panorama を含むか決められない表記や、形の違う `platforms`（文字列・中身が文字列でない など）は、どの機器にも「候補」です。platforms は全件で判定します（理由の文だけ切り詰めます）。5. の既定の扱いにも同じ絞り込みをかけます。**defaultStatus は同じ製品行（`affected[]` の 1 件）に載っている系列だけで判断します**（別の製品行に載っている系列で打ち消しません）
  6. 影響ありの行と影響なしの行が同じ版に重なるとき（本物では見ていない形）は、どちらにもせず「判定できない」
  7. 読み取れない行は該当にも非該当にもせず「判定できない」: `status` が `unknown` など、版・修正点・上限が読めない、`versionType` が `custom`・無し・空 以外、`changes` に status `affected`（修正のあとにまた影響あり）、修正点が範囲の始まり以前、同じ保守版に修正点が 2 つ、`lessThan` と `lessThanOrEqual` が両方、など。上限が `10.2.*` の行は「その系列の `version` 以上すべて」。**系列をまたぐ行**（上限・修正点が別の系列にある。例: `version 9.1.0, lessThan 11.0.0`）、**上限が `*`**（その系列だけか全体か決められない）、**語句つきの版**（`10.1 and earlier`・`10.2 and later`・`10.2.0 - 10.2.5` など）は、系列なしの読めない行として**全系列で**判定できないにします。`x.y` を系列として読むのは、版の全体が `x.y`・`x.y.z`・`x.y.z-hN`・`x.y.x`・`x.y.*`・`x.y*`・`x.y All`・`x.y None` のときだけです。影響なしの `"x.y None"` がある系列は、同じ製品行のその系列の判定に使える行が `"x.y All"` の影響ありだけのときに限って確定（該当）し、それ以外の組み合わせ（対の行が無い・ほかの範囲の行がある）は「判定できない」です。製品名の系列と版の系列が違う行（`PAN-OS 11.1` に `version 10.0.0`）、製品名に `PAN-OS` を含むのに決まった形でない製品行（`PAN-OS®`・`PAN-OS 11.1.x`・`PAN-OS (Panorama)`）も全系列で判定できないです。`lessThan` が `changes` に無く `changes` の最大より前にある行は、その系列を判定できないにします（`changes` が空で `lessThan` だけの行は読みます）。`lessThanOrEqual` が `x.y.z`（ホットフィックスなし）のとき、同じ `x.y.z` のホットフィックスの版は判定できないです
  - 取得のときに行を正規化して保存し（`vuln_fetch.py` の `ranges_from_versions`）、元の値（`version`・`lessThan`・`lessThanOrEqual`・`changes`・`status`・`versionType`・`defaultStatus`・`platforms`・製品名）も `src` に残します（勧告の詳細の API で見られます）
  - **方針**: はっきり認識できた形だけで該当・非該当を決め、それ以外は必ず「判定できない」か「候補」にします。非該当にする枝ごとの根拠は `vuln_match.py`（`_gate` の skip・`_span` の out・`_judge` の最後）にコメントで書いています。性質のテストで「読めない行を 1 つ足しても、該当・判定できない・候補が非該当に変わることは無い」ことを確かめています
  - **読めない行の扱い**: 系列を読み取れた読めない行は、その系列の機器だけを「判定できない」にします（`x.y` を系列として読むのは、上の 7. のとおり版の全体が決まった形のときだけです）。系列を読み取れない行（`version` が空・語句つき など）は、どの系列にも関わりうるので、ほかの行で「該当」と決まった機器は該当、それ以外は「判定できない」にします（見落としを避けるため）。本物で残っている系列の無い読めない形は、`version: ""` の行（`status: unknown` の PAN-SA、`status: affected` で `defaultStatus: unaffected` の勧告）で、そのような勧告はすべての機器で「判定できない」になります
  - **版が変わって判定できなくなった「該当」**: 判定を出したときの版と機器のいまの版が同じなら、範囲を読めなくても前回の判定を据え置きます。版が違えば「該当」のまま数えず、該当の件数・一覧から外して「判定できない機器」のタブに「前回（版 X）は該当。版が変わり、いまの版では判定できません」と出します（未確認・確認済みの状態とメモは残します。版が戻るか、判定できる版になれば外れます）。版が読めなくなった機器も同じで、脆弱性の対象外の platform に変わった機器は版を問わずこの扱いです。判定を出したときのモデルも記録し、モデルが変わっていて判定できないときも同じ扱いです。版・モデルは前後の空白を除いて比べます（モデルは大文字小文字も無視）
  - **限界**: 判定は勧告の JSON の範囲だけを見ます。勧告の本文にだけ書かれた条件（例: 「Panorama は影響を受けない」が `platforms` に表れていない勧告）は反映されません。保守版の間の版（例: 修正点が `12.1.4-h7` と `12.1.7` のときの `12.1.5`）は、修正を含むかを JSON から確かめられないため、最大の修正点より前なら「該当」に倒します。`platforms` の機種の系列（PA-3200 系列）と機器のモデル（PA-3220 など）の対応は判別しません（候補として出すだけです）。影響なしの行（platforms なし）と Panorama だけの影響ありの行が同じ版に重なる勧告は、モデルが空・判別できない機器で「判定できない」になります（ファイアウォールと判別できれば非該当、Panorama なら食い違いで判定できない）。defaultStatus が無い製品行は「記載のない系列は影響なし」として扱います（CVE JSON 5.0 の決まりでは unknown ですが、本物の古い記録に defaultStatus が無く、それらの勧告のページの表は全系列を載せているため）。Panorama だけの製品行に読めない行があると、ファイアウォールも「判定できない」になります。`version: ""` で影響ありの行がある勧告（defaultStatus が unaffected でも）は、すべての機器で「判定できない」になります
  - **勧告の取り下げ**: 応答で `state: REJECTED` と分かった保存済みの勧告は「取り下げ」とし、照合に使わず、その勧告の未確認・確認済みの判定を解消にします（メモは残します。再び公開されたときに該当すれば、確認済みの印とメモを残したまま戻します。再公開のときに非該当なら、取り下げの印を外してふつうの解消にし、あとで該当したらふつうの新しい該当として未確認で開きます）。記録として読めなかった勧告（`affected` が配列でない・`containers.cna` が無い・`state` が想定外 など）は取得の記録の「読めなかった件数」に数え、ID が分かれば「範囲を読み取れない」勧告として残します（保存済みなら上書きし、前回の該当は古い範囲によるものなので「判定できない」側に移します）。改訂で影響なしの行だけになった保存済みの勧告は、範囲を空にします（照合で解消になります）。応答から消えただけの勧告は、取得の一時的な欠けと区別できないため、そのまま残します（古い範囲で該当が出続けることがあります）
- **Panorama だけに影響する勧告**: 勧告の影響範囲に `platforms: ["Panorama"]` が付いているものは、機器のモデルで判定します。Panorama（モデルに Panorama を含む、または M-100・M-200・M-300・M-500・M-600・M-700）は範囲どおり、ファイアウォール（PA-・VM-・PA-VM で始まるモデル。前に `PAN-` が付く書き方も）には当たりません。**モデルが空・判別できない機器は「該当」にせず「候補」**として出し、「Panorama だけに影響する勧告です。機器の種類を判別できませんでした」と注記します（収集でモデルが分かると、確定または外れます。画面の「候補」は、この理由か、上の 5.・5-2. の理由で出るものです）
- **範囲を読み取れない勧告**: 上の 7. の読み取れない行は、**該当にも非該当にもせず**、その機器×勧告を「判定できない」として数えます。画面の上部に「範囲を読み取れなかった勧告が n 件あります」と出し、「判定できない機器」のタブに機器と勧告の ID を並べます。取得のとき読めなかった行の数は、情報源の記録に残ります（すでにある判定は、読めない範囲のせいで「解消」にはしません）
- CVSS は、PAN-OS に結び付く点を採ります（場面の説明に Prisma Access・Cloud NGFW だけが出てくる点は除く）。区別できなければ、勧告の点のうち最も高いものです
- endoflife.date の API は Beta で、形が変わることがあります。形が変わっても落ちずに、その情報源を「取得に失敗」と記録します（取れた製品の分は保存します）
- Palo Alto の API も Beta（公式の案内に「予告なく変わる・廃止されることがある」と書かれています）。**形が変わると取得に失敗します（そのときは画面の上部とシステム状態に出ます）**。応答は 1 回で全件が返り、続きを示す項目（next・total など）はありません（2026-11 時点。出てきたら記録に警告を残します）。`/json?product=PAN-OS` の形は、この環境では確認できなかったため、製品単位で取れることを確認できた `/api/v1/products/PAN-OS/advisories` を使っています

### 有効にする

1. `.env` に `VULN_ENABLED=true` を追加する（`.env.example` の「脆弱性」の節を参照）。プロキシを通す・HTTPS を検査するプロキシの CA を信頼するときは、下の「外部への接続（プロキシ・組織の CA）」の `OUTBOUND_PROXY`・`OUTBOUND_CA_FILE` を設定します（以前の `VULN_HTTPS_PROXY` は廃止しました。`.env` に残っていても起動は止まらず、無視します。`OUTBOUND_PROXY` に移してください）
2. サーバーから、下の「通信先」へ HTTPS（443 番）で接続できることを確かめる（社内のプロキシ・ファイアウォールの許可）
3. `bash scripts/setup.sh` でコンテナを作り直す（メニュー「監視」に「脆弱性・サポート期限」が出ます）
4. 毎日 `VULN_FETCH_HOUR`（既定 4 時。`TIMEZONE` の時刻）以降の最初の判定で取得します。すぐ取りたいときは、画面の「いま取得」（管理者のみ。5 分に 1 回まで）

無効に戻すときは `VULN_ENABLED=false` にしてコンテナを作り直します（取得した勧告・照合結果・手入力の日付は残り、再度有効にすると続きから使えます）。

### 取得のしくみ

- worker の `fetch_vulns` を beat が**毎時**に呼び、「今日まだ成功していない情報源」だけを取ります。失敗した情報源は 3 時間あけて再試行します。1 つの情報源の失敗で、ほかは止まりません。結果（最後の成功・失敗の理由・件数）は情報源ごとに記録し、画面の上部に出します
- 宛先は固定の一覧（`vuln_fetch.py` の `ALLOWED_HOSTS`）だけ。https のみ・リダイレクトも一覧の中だけ・接続・1 回の読み取りは 10 秒、**TLS のハンドシェイクとヘッダーの受信を含めて全体 60 秒**（相手が少しずつ返し続けても、期限でソケットを閉じて打ち切ります）・応答は 50MB まで。相手の不正な応答（途中で切れる・形式が違う）は失敗として記録し、相手が返した文字列は載せません。応答は JSON だけを標準ライブラリで読みます。失敗の理由には、URL・プロキシの認証情報・相手の応答の本文を入れません
- プロキシと TLS の信頼は「外部への接続」の共通の設定（`OUTBOUND_*`）を使います。接続そのもの（許可リスト・期限の見張り・CONNECT）はこの機能の専用のままです
- 外から来た文字列（勧告の題・URL）は長さを切り詰めます。URL は https で一覧のホストのものだけ保存し、画面ではテキストとして表示します（リンクは `rel="noopener noreferrer"` の新しいタブ）
- 取得のあと全機器を照合し、機器の OS バージョンが変わったとき（収集のあと）は、その機器だけ照合し直します（外部へはつながりません）
- 判定の移り変わり: 新しく該当 → 未確認（open）／「確認済み」（メモ必須。対応不要・対応済みの予定）／バージョンが上がって影響範囲から外れる → 解消（fixed。確認済みも解消になります）／また該当したら未確認に戻る。OS バージョンが読めなくなった機器の判定は変えません

### 通信先（サーバーから出る通信）

| ホスト | 用途 | 使う設定 |
|---|---|---|
| `security.paloaltonetworks.com` | Palo Alto の勧告 | `paloalto` |
| `www.cisa.gov` | 悪用確認済み一覧 | `kev` |
| `endoflife.date` | サポート終了日 | `eol` |

（Fortinet の勧告・NVD 用のホストも許可リストには入っていますが、この版では接続しません。）`VULN_ENABLED=false` のあいだ、これらへの通信は行いません。

### 画面（メニュー「監視」の「脆弱性・サポート期限」）

- 上部: 注意書きと出典、要約（重大・高・悪用確認済み・候補・サポート終了済みの機器数・1 年以内に終了する機器数）、情報源ごとの最後の取得（失敗はその理由）
- タブ: **脆弱性**（機器 × 勧告の一覧。重大度・悪用確認済み・「該当」の区別・出典へのリンク・状態の絞り込み・CSV 出力・「確認済みにする」）／**機器別**（機器ごとの件数）／**サポート期限**（機器ごとの OS・ハードウェアの終了日と残り日数、手入力の編集。残り日数は TIMEZONE の今日から数えます）／**判定できない機器**（理由つき）
- 「確認済みにする」はオペレーター以上。メモが必須で、誰がいつ付けたかを監査ログに残します
- システム状態に「脆弱性情報の取得」の項目が出ます（有効なときだけ。最後の成功・失敗している情報源・3 日以上取得できていないと注意）

### 権限

- 閲覧（要約・一覧・CSV・サポート期限）: 閲覧者以上（機器と OS バージョンを見られるため）
- 確認済み・その取り消し・サポート終了日の手入力と削除: オペレーター以上（監査ログに残ります）
- 「いま取得」: 管理者のみ（監査ログに残ります）
- API トークン: 閲覧の API は呼べます（範囲 `read` でも可）。確認済み・手入力・いま取得は、ログインのセッションからだけです

## 通知（Discord / Slack / Teams / メール）

コンフィグの変更・コンプライアンス違反の発生・収集の失敗・機器情報の変化・Ping監視の応答なしと復旧・基準からのずれ・保存し忘れを、Discord・Slack・Teams の Webhook とメールで通知します。「通知設定」画面で設定します（メールの送信の設定は下の「メール通知」）。

- **通知する内容**（通知設定ごとに選択。既定はコンフィグの変更・機器情報の変化・Ping監視・システムの異常）
  - コンフィグの変更: 収集で設定の変更が見つかったとき
  - コンプライアンス違反の発生: 新しく違反になったとき（解消・除外は通知しません）。機器名・違反したルールと重要度、違反一覧へのリンク。ルールの追加などで多数の機器が同時に違反になったときは、通知先ごとに1通にまとめます
  - 収集の失敗: 再試行しても収集できなかったとき（認証失敗など再試行しないものはすぐ）。機器名・エラー・アクティビティへのリンク
    - **短い時間の失敗はまとめます。** 最初の失敗から `NOTIFY_FAILURE_BATCH_SEC` 秒（既定 60 秒）の間に起きた失敗を、通知先ごとに 1 通にまとめて送ります。ネットワーク障害などで一括収集・スケジュール収集の多くの機器が同時に失敗しても、通知があふれないようにするためです
    - まとめた結果が 1 台なら、これまでどおり機器ごとの詳しい通知です。2 台以上なら「収集失敗: ○ 台」として、失敗の理由の内訳（理由ごとの台数）と機器の一覧（20 台まで）を送ります。同じ機器が何度も失敗した場合は最後のものだけです
    - そのため、失敗の通知は最大でこの秒数だけ遅れて届きます。すぐに受け取りたい場合は `.env` に `NOTIFY_FAILURE_BATCH_SEC=0`（機器ごとにすぐ送る。変更後は `setup.sh`）
  - Ping監視: 常時監視している機器・IP が続けて応答しなくなったとき・応答が戻ったとき（下の「Ping監視」の「常時監視」）。同時に起きたものは 1 通にまとめます
  - 機器情報の変化: 収集のついでに読み取った OS バージョン・シリアル番号・モデル・機器側のホスト名が前回と変わったとき（下の「機器台帳の自動取得」）。機器名・変わった項目（以前 → 今回）・アクティビティへのリンク。シリアル番号・モデルの変化は件名を「機器の交換？」にして、登録内容の確認を促します。初めての取得・読み取れなかったときは送りません
    - この項目を追加する前からある通知設定は、「コンフィグの変更」を選んでいるものだけ有効になります
  - 基準からのずれ: 基準の世代を指定した機器のコンフィグが、基準と違う状態になったとき（ずれなし → ずれあり。上の「基準の世代（ベースライン）とずれの検出」）。**既定は無効**です。機器名・ずれの行数・基準と最新の世代・画面へのリンク。基準を指定した直後・すでにずれている間は送りません
  - 保存し忘れ: running-config が startup-config に保存されていない状態になったとき（下の「保存し忘れの検出」）。**既定は無効**です。機器名・グループ・保存されていない変更の行数・画面へのリンク。差分の中身は送りません。一致 → 未保存に変わったときだけ送り、初めて比べられた回・保存されないままの間は送りません
  - システムの異常: worker・スケジューラーの停止、長期間収集できていない機器、ディスクの空き、証明書の期限（「システム状態」を参照）。対象の機器グループに関係なく送ります

- **変更通知の内容**: 機器名・IP・機器のグループ・変更行数（+n / -n）・収集の種類と時刻・世代と、差分画面へのリンク。差分の中身（パスワードのハッシュ等を含みうる）は送りません
- **自分の通知**（全ユーザー）: 次のどれかを選びます
  - 所属グループの設定を使う（既定）: 所属するユーザーグループのうち、通知が有効なものの通知先・対象で通知
  - 個別に設定する: 自分の Webhook・メールの宛先と、通知する機器のグループ（すべて / 選択したグループ / 未分類）を指定
  - 通知しない
- **ユーザーグループ**（管理者）: チームを作ってメンバーを登録し、グループの通知先・対象を設定します。1人が複数のグループに所属できます
- 同じ Webhook・メールの宛先へは1回だけ送ります（グループの Webhook はメンバーが何人いても1回）。「所属グループの設定を使う」メンバーがいないグループの Webhook には送りません
- 初回の取得は変更ではないため通知しません。通知の送信は収集とは別のタスクで行い、失敗しても収集には影響しません
- 「テスト通知を送る」で通知先を確認できます。最後の送信結果（失敗時は理由）も表示します
- 管理者は「通知先の確認」で、機器のグループと通知の内容ごとにどこへ送られるかを確認できます
- Webhook URL は暗号化して保存し、画面では Discord・Slack は末尾4文字だけ、Teams はホストの先頭4文字だけ表示します（Teams の URL は末尾に署名 `sig=` を含むため、末尾は出しません）。宛先は Discord（`https://discord.com/api/webhooks/…`）・Slack（`https://hooks.slack.com/…`）・Teams（下の「Teams への通知」）の公式の URL に限ります
- リンク先は `.env` の `PUBLIC_URL`（例: `https://192.168.1.10`）。`setup.sh`・`import_cert.sh` が未設定のときに IP アドレスから設定します。空ならリンクなしで送ります
- サーバーから Discord・Slack・Teams（インターネット）へ HTTPS で接続できる必要があります
- 設定の変更・テスト通知・ユーザーグループの変更は監査ログに残ります

### Teams への通知

Teams のチャネル・チャットへ、「ワークフロー」（Power Automate）の **Webhook 要求を受信したとき** のフローを宛先にして通知します。本文は Adaptive Card（題・項目の一覧・本文・画面へのリンクのボタン）で、送る内容・要約と画面へのリンクのみという方針は Discord・Slack と同じです。旧 Office 365 コネクタの Webhook（`webhook.office.com`）は廃止されたため対応しません。

設定手順（Teams 側）:

1. Teams で、通知を受け取りたいチャネル（またはチャット）の「…」から「ワークフロー」を開き、「Webhook 要求を受信したときにチャネルに投稿する」（チャットなら同様のテンプレート）を選ぶ（テンプレートの名前・画面は Teams の版によって異なります）
2. フローの名前を付けて作成すると、**Webhook の URL**（`https://xxxx.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/…/triggers/manual/paths/invoke?…&sig=…`）が表示されるのでコピーする（`sig=` を含む最後までコピーします）
3. NetConfig Manager の「通知設定」で、「個別に設定する」（管理者はユーザーグループの通知も同様）の **Teams の Webhook URL** へ貼って保存し、「テスト通知を送る」で届くことを確認する

注意:

- **URL の検査（安全のため、任意の URL へは送りません）**: `https://` のみ。ホストは `<名前>.environment.api.powerplatform.com`（英数字・ハイフン・ドットだけ。IP アドレス・日本語などのドメイン名・末尾のドット・`@`（ユーザー情報）は不可）。ポートは無し・443 のみ。パスは `/powerautomate/automations/direct/` を含んで `/triggers/manual/paths/invoke` で終わる。クエリに `sig=`（1 つ）が必要。`#` 以降・空白・制御文字・バックスラッシュ・1024 文字を超えるものは不可
- 旧形式（`*.logic.azure.com`）の URL は、2025/11/30 で使えなくなったため登録できません。ワークフローの画面から Webhook のリンクをコピーし直してください
- 送信はリダイレクトをたどりません（Discord・Slack は従来どおり）。成功は 2xx（Power Automate は 202 を返します）。429 は一度だけ待って再送します
- URL・`sig=`・ワークフローの ID は、画面・ログ・アクティビティ・監査ログ・送信の失敗の理由（最後の通知のエラー）に残しません。URL は暗号化して保存します（`DEVICE_ENCRYPTION_KEY` を失うと復号できません）
- 同じ URL（グループと個人など）へは 1 回だけ送ります
- ワークフローがオフ・削除・URL の再発行をされると「Webhook が無効です」になります。ワークフローの実行の履歴は Power Automate 側で確認できます
- ワークフローの**トリガーを実行できるユーザーは「誰でも」**にしてください。「組織内のユーザー」に限ると、認証のない POST のこのアプリからは送れません（設定の名前は Teams の版で変わることがあります）
- Teams のカードでは、機器名・ルール名・エラー文などの中の Markdown のリンクの構文（`[文字](URL)`・画像）を、`](` の間にゼロ幅スペースを入れて無効にしています（偽のリンクを通知に出せないように。正当なリンクはボタン（Action.OpenUrl）だけです）。太字などの書式は無効にしません
- **Discord・Slack でも、偽のリンク・メンションを出させません**（機器名・グループ名・ルール名・Ping の名前・機器情報の値・エラー文・プロファイル名・利用者名など、利用者・機器が決められる文字列だけを対象に、固定の文言・自分で組み立てるリンク・絵文字・改行は変えません）。Discord は埋め込みの題・説明・項目の値の `](` の間にゼロ幅スペースを入れてリンクの構文を無効にし、送る JSON に `allowed_mentions: {"parse": []}` を付けて `@everyone`・`@here`・`<@id>` で通知が飛ばないようにします。Slack は `&`・`<`・`>` を `&amp;`・`&lt;`・`&gt;` に置き換え、`<url|文字>`・`<!channel>`・`<@U…>` を働かなくします（入力にある `&amp;` はそのままの文字として見えます）。行頭の `#`・`>`・`-` などの書式は無効にしません。無害化の関数は `services/notify.py`（`break_md`・`slack_escape`）の 1 か所で、定期レポート（`services/report.py`）も同じものを使います。メールは HTML に入れる値をすべて `html.escape` します
- カードが約 24KB を超えるときは、本文・項目の値を切り詰めて送ります
- HTTP のエラーのとき、相手の応答の本文は「最後の通知のエラー」に載せません（コードと案内だけ）
- Teams の本文の改行は、表示が詰まらないよう段落（空行）にして送ります
- **実際の Teams へは送って確かめていません（実環境未確認）。** 本文は Adaptive Card（version 1.4）の標準の形で作り、試験では送信先を差し替えて形と動きを確かめています。導入時は「テスト通知を送る」で表示（改行・リンクのボタン）を確認してください

### 定期レポート（週次・月次）

期間内の状況をまとめて、通知設定の宛先（Discord・Slack・Teams・メール）へ定期的に送ります。監査・報告用です。「通知設定」の **定期レポート**（送らない／毎週／毎月／両方。既定は送らない）で選びます。ユーザーグループの通知にも同じ選択があります。通知する内容（変更・違反など）とは独立で、レポートだけを選んだ設定も保存できます。

- **送る日と取り戻し**: `REPORT_HOUR`（既定 8 時。`TIMEZONE` の時刻）。週次は月曜（前の月〜日曜の 7 日間）、月次は 1 日（前の月）の `REPORT_HOUR` 時に送ります。worker の毎時の判定（`send_periodic_reports`）が、まだ送っていない期間を **取り戻しの期間のあいだ** 送ります。取り戻しの期間は、期間の終わり（月曜 0 時・1 日 0 時）から、週次は 7 日と `REPORT_HOUR` 時間（次の月曜の `REPORT_HOUR` 時まで）、月次は 27 日と `REPORT_HOUR` 時間（28 日の `REPORT_HOUR` 時まで）です。初日は `REPORT_HOUR` 時以降、翌日以降は終日送れます。たとえば週次（2/23〜3/1）は、3/2（月）8:00 から次の月曜 3/9 の 7:59 まで取り戻せ、3/9 の 8:00 からは新しい週（3/2〜3/8）の分だけを送ります（先週分とは重なりません）。このため、月曜・1 日に worker が止まっていても、起動後に送れます。1 日が月曜なら週次と月次を別々に送ります
- **設定した直後に過去の分を送らない**: 種類（週次・月次）ごとに、その種類が「無効 → 有効」になった時刻を `notification_settings.report_week_since` / `report_month_since` に記録し、**それより前に終わった期間は送りません**（毎週を選んだ直後に先週分が届くことはありません）。有効のままの種類は変えないので、毎週 → 両方にしても、すでに有効だった週次は止まりません（月次は設定後に終わった期間から）。種類を無効にすると消えます。通知の設定を「個別に設定する」以外にしていた期間は無効として扱い、戻したときに、止めていた期間の分を送ったり「送れませんでした」と残したりしません。API を通さずに作られた行で、有効な種類の記録が空のものは、最初の判定で「その時刻」を入れ、その回は送りません。`updated_at` は通知の送信でも変わるため使いません
- **送れなかった回の記録**: 取り戻しの期間を過ぎても送れなかった回（3 回とも全宛先で失敗した・worker がずっと止まっていた）は、アクティビティに「定期レポートを送れませんでした（週次 2/23〜3/1・ユーザーの設定）」を 1 回だけ残し、`report_sends` の行を `missed` にします（毎時はくり返しません）。送れなかった回は、あとから送りません
- **送る設定**: 利用者の設定は「個別に設定する」のもの。ユーザーグループの設定は、有効で、「所属グループの設定を使う」メンバーが 1 人以上いるもの（通知の宛先の決め方と同じ）。設定ごとに 1 通で、その設定の「通知する機器」の範囲（すべて／機器グループ／未分類）の機器だけで集計します。範囲外の機器名・件数は混ざりません
- **二重に送らない**: 送る前に (設定, 種類, 期間の最初の日) の行を `report_sends` に作り、作れた worker だけが送ります（一意制約。worker の再起動・タスクの重複・beat の二重起動・同時に判定した 2 つの worker でも 1 回。PostgreSQL・SQLite とも）。すべての宛先で失敗したときだけ、次の毎時の判定でやり直します（3 回まで）。一部の宛先に送れれば送信済みです。送信中のまま止まった行は 30 分たつと（これも 3 回まで）引き継ぎます。**引き継いだときは、途中まで送った宛先に同じレポートを再送することがあります**。判定のたびに、その期間の行を 1 回の SELECT でまとめて読み、送信済み・送信中の設定は INSERT を試しません（PostgreSQL のログに重複エラーを出さないため。同時に判定したときの一意制約による保護は残しています）。古い行は毎日の掃除で消えます
- **失敗**: 1 つの設定の判定・送信で例外が出ても、ほかの設定・ほかの種類（月次）の判定は続けます（失敗はログとアクティビティに残します。例外の文言は載せません）。失敗した宛先があっても、ほかの宛先には送ります。失敗は通知設定の最後の通知の結果（`last_error`）とアクティビティ（通知の失敗）に残ります（Webhook の URL などの秘密は含めません）
- **中身**（機器名・ルール名・件数だけ。コンフィグの中身・Webhook・認証情報・利用者のメールアドレスは入れません）:

| 項目 | データの出どころ | 件数 |
|---|---|---|
| 収集の成功・失敗の回数 | 収集の履歴（成功）、アクティビティの収集失敗（再試行しても失敗した最終の失敗） | 期間内 |
| 失敗が続いている機器（上位 10） | 期間内の最後の成功のあとに 2 回以上失敗した機器 | 期間内 |
| 変更のあった機器数・件数・変更の多い機器（上位 10） | 世代（初回の世代は除く） | 期間内 |
| 変更のうち未確認 / 未確認の変更の残り | 変更の確認の状態 / 直近 `CHANGE_REVIEW_DAYS` 日 | いま |
| 新しく出た違反・解消した違反 | アクティビティの違反の発生・解消（一括で記録されたものは一覧から数えます） | 期間内 |
| いまの違反（重要度別） | コンプライアンスの結果 | いま |
| 基準の世代からのずれ・保存し忘れ | 基準の世代・機器の状態（履歴は残していない） | いま |
| Ping監視の応答なし（回数・上位 5） | アクティビティの Ping監視（機器と追加した IP） | 期間内 |
| 管理者向け: 2 段階認証を設定していない利用者数 / 証明書の期限 / 30 日以内に期限が切れる API トークン | 利用者・システム状態・API トークン | いま |
| 管理者向け: ログインの一時停止の回数 | 監査ログ | 期間内 |

  管理者向けの項目は、管理者（`system:read` を持つ利用者）の「個別」の設定のレポートだけに入ります（機器に結び付かないため、グループの設定には入れません）。期間内に何も無かったときも、「変更なし」と分かる短いレポートを送ります。本文の先頭に「集計: 年/月/日 時:分 時点」を入れます（取り戻しで送ったときに、「いま」の件数がいつの時点かが分かります）。アクティビティ・監査ログの保持期間（`ACTIVITY_LOG_RETENTION_DAYS`・`AUDIT_LOG_RETENTION_DAYS`）より前の期間を含むときは、一部しか集計できない旨を注記します
- **本文と長さ**: メールの件名は「週次レポート 11/16〜11/22」（先頭に送信の設定の件名の接頭辞）で、本文はテキストと HTML。Discord（埋め込み全体 6000 文字・項目 1024 文字）・Slack（3000 文字）・Teams（カード 24KB）は、上位の一覧の件数を減らして収め、「ほか n 件」と書きます。機器名・ルール名は、Teams と Discord ではリンクの構文を無効にし、Slack では `<!channel>` などが働かないようエスケープします
- **画面**: 通知設定で「個別に設定する」を保存すると、「定期レポートの確認」で先週・先月の集計をプレビューできます（送りません。保存済みの個別設定の範囲で集計。「所属グループの設定を使う」「通知しない」のときは欄を出しません）。「いま送る」は、保存済みの自分の通知先へ直前の期間のレポートを今すぐ送ります（送信中は押せません）。プレビューは利用者ごとに 3 秒、「いま送る」は 60 秒の間隔を空けます（連打は 429）
- **範囲の判定**: 機器がどの範囲に入るかは、レポートを作る時点の機器の所属グループで判定します（期間の途中で機器のグループを移すと、移す前の分も新しい範囲に入ります）。設定を消して作り直すと、送信済みの記録（設定の ID に結び付く）が切れるため、同じ期間をもう一度送ることがあります
- **集計の負荷**: レポートは設定ごとに集計します（機器・記録の数に応じた数回のクエリ）。設定が多い（数十以上）と、送る時刻に集計が集中します。数百台・数十設定の規模なら数十秒〜数分の見込みで、worker の 1 つのタスクの中で順に処理します（実測はしていません）。集計を期間ごとに 1 回にまとめる改良は今後の拡張ポイントです
- **API**: `GET /api/notifications/report-preview?period=week|month`（自分の設定の範囲で集計を返す）、`POST /api/notifications/me/report?period=week|month`（自分の宛先へ送る。監査ログ `notify.report_send`）。権限は通知設定と同じ（`notify:self`）で、API トークンでは使えません（セッションのみ）
- **実環境未確認**: 実際の Discord・Slack・Teams・メールへは送って確かめていません（試験では送信先を差し替えて、本文・長さ・二重送信の防止を確かめています）。導入時は「いま送る」で表示を確認してください

### メール通知

通知設定の「自分の通知」「ユーザーグループ」でメールの宛先（10 件まで）を登録すると、Webhook と同じ内容（件名・要約・画面へのリンク。テキストと HTML）をメールで送ります。宛先ごとに 1 通ずつ送り、ほかの宛先は見えません。送信の設定は、管理者が「通知設定 → メールサーバー」で行います。

| 認証の方式 | 使う場面 | 設定する値 |
|---|---|---|
| SMTP Auth（ユーザー名＋パスワード） | 社内のメールサーバー、Gmail のアプリパスワード、送信サービス | ユーザー名・パスワード |
| Microsoft 365（OAuth 2.0） | Exchange Online | テナント ID・クライアント ID・クライアントシークレット、送信に使うメールボックス |
| Google Workspace（サービスアカウント） | Google Workspace（ドメイン全体の委任） | サービスアカウントの鍵（JSON）、送信者のアドレス |
| Google アカウント（OAuth 2.0・同意） | 個人の Gmail など | OAuth クライアント ID・シークレット（デスクトップ アプリ）、画面で一度同意 |
| 認証なし | 送信元の IP で許可している社内のリレー | — |

- 暗号化は STARTTLS（587）・SSL/TLS（465）・なし（社内のリレーだけ）。OAuth 2.0 では暗号化が必須です。社内の自己署名の証明書なら「証明書を確認しない」を選べます（通信の盗み見に気づけなくなるため、できれば使わない）
- パスワード・クライアントシークレット・サービスアカウントの鍵・Google の更新用トークンは `DEVICE_ENCRYPTION_KEY` で暗号化して DB に保存し、画面には表示しません（空欄で保存すれば変更なし）
- OAuth 2.0 のアクセストークンは送信のときに自動で取得・更新し、有効期限の少し前まで使い回します。取得先は Microsoft・Google の決まったアドレスだけです
- **宛先に使えるドメイン**を指定すると、それ以外のアドレスは宛先に登録・送信できません（閲覧者も自分の宛先を登録できるため、社外へ送らせないときに指定します）
- 「テストメールを送る」で設定を確かめられます。失敗の理由（認証の失敗・接続できない・証明書を確認できないなど）を日本語で表示します
- 最後の送信の結果は「システム状態」の「メール送信」に表示し、失敗すると異常として（ほかの通知先へも）通知します。通知の失敗はアクティビティにも残ります（宛先のアドレスは残しません）
- Microsoft 365 はパスワード（基本認証）での SMTP 送信を 2026 年 12 月末から既定で無効にし、最終的に廃止する予定です。Google もアカウントのパスワードでは送れません（アプリパスワードか OAuth 2.0）
- サーバーから SMTP サーバー（と、OAuth 2.0 なら login.microsoftonline.com・oauth2.googleapis.com）へ接続できる必要があります

**Microsoft 365 の準備**（Exchange Online の管理者）

1. Entra ID の「アプリの登録」で新しいアプリを作り、「API のアクセス許可」で「Office 365 Exchange Online → アプリケーションの許可 → SMTP.SendAsApp」を追加して、管理者の同意を与えます
2. 「証明書とシークレット」でクライアントシークレットを作成します（**期限があります。切れる前に作り直して画面で更新**）
3. Exchange Online PowerShell で、アプリのサービスプリンシパルを登録し、送信に使うメールボックスへの権限を与えます

```powershell
Connect-ExchangeOnline -Organization <テナント ID>
# AppId: アプリケーション（クライアント）ID
# ObjectId: 「エンタープライズ アプリケーション」の概要のオブジェクト ID（アプリの登録の画面の値ではない）
New-ServicePrincipal -AppId <AppId> -ObjectId <ObjectId>
# User: 上で作ったサービスプリンシパルの ID（Get-ServicePrincipal | fl で確認）
Add-MailboxPermission -Identity "notify@example.com" -User <サービスプリンシパルの ID> -AccessRights FullAccess
```

4. 送信に使うメールボックスで SMTP AUTH が有効になっていること（`Set-CASMailbox -Identity notify@example.com -SmtpClientAuthenticationDisabled $false`）
5. 画面で SMTP サーバー `smtp.office365.com`・587・STARTTLS、送信に使うメールアドレスと送信元に同じメールボックスを設定します

**Google の準備**

- Google Workspace（サービスアカウント）: Google Cloud でサービスアカウントを作って鍵（JSON）を作成し、Workspace の管理コンソール（セキュリティ → API の制御 → ドメイン全体の委任）でサービスアカウントのクライアント ID にスコープ `https://mail.google.com/` を許可します
- Google アカウント（同意）: Google Cloud で OAuth クライアント ID（種類: **デスクトップ アプリ**）を作ります。画面でクライアント ID・シークレットを保存して「Google にサインイン」→ 送信者のアカウントで許可 → ブラウザが `http://127.0.0.1` を開いて「接続できません」と表示するので、そのページのアドレス欄をすべてコピーして画面に貼り付けます（10 分以内）。サーバーのホスト名を Google の戻り先に登録できなくても使えるよう、この方式にしています。OAuth の同意画面が「テスト中」のままだと、更新用トークンは 7 日で切れます（「本番環境」にしてください）

## 左ペインのメニュー（大項目・小項目）

画面左のメニューは、「ダッシュボード」（単独）と 4 つの大項目に分かれています。大項目の見出しを押すと、中の小項目が開閉します（複数の大項目を同時に開けます）。

| 大項目 | 小項目（この順） |
|---|---|
| ダッシュボード | （単独。一番上） |
| 機器 | デバイス管理 / 構成図 / ターミナル / コマンド実行 / 踏み台サーバ / 認証情報プロファイル |
| コンフィグ | コンフィグ収集 / スケジュール / 世代管理 / 変更の確認 / コンフィグ検索 / コンプライアンス / 無視する行 |
| 監視 | Ping監視 / モニタリング（有効時のみ）/ 脆弱性・サポート期限（有効時のみ）/ アクティビティ |
| 管理 | 通知設定 / ユーザー管理 / 監査ログ / システム状態 |

- 開いている画面を含む大項目は、自動で開きます。手で閉じても、別の画面へ移ると開きます。閉じた大項目の中にいま開いている画面があるときは、見出しを選択中の色にします
- 開閉の状態は**ブラウザ**にユーザーごとに覚えます（localStorage の `ncm.nav.open.<ユーザー名>`。保存できなくても動きます）。初めての人は、いまの画面を含む大項目だけが開いた状態です
- 権限や機能の条件（モニタリング・脆弱性が無効など）で見られる小項目が 1 つも無い大項目は表示しません（例: 権限を絞ったロールでは、「管理」などの大項目ごと出ません）。閉じている大項目の小項目は描画しません
- 「管理」を閉じているときにシステム状態に注意・異常があると、「管理」の見出しに同じ印（黄・赤）を出します
- 見出しは button（`aria-expanded` / `aria-controls`）で、Enter / Space で開閉できます
- このあとの説明の「メニューの○○」は、上の表の小項目を指します

## ダッシュボード

ログイン後の最初の画面です（閲覧者以上）。「いま確認が必要なこと」を1画面にまとめています。

- **数値**: 有効な機器の台数、最新の収集が失敗している機器、一度も収集していない機器、直近 24 時間・7 日間のコンフィグの変更、未確認の変更（直近 `CHANGE_REVIEW_DAYS` 日。想定外があれば件数を併記）、基準からずれている機器（基準を指定した機器があるときだけ）、保存されていない変更（対象の機種の機器があるときだけ。押すとデバイス管理を開きます）、コンプライアンス違反（重要度別）。押すと該当の画面（アクティビティ・コンフィグ収集・変更の確認・コンプライアンスなど）を開きます
- **確認が必要な機器**: 収集に失敗している機器（エラーの内容・いつから）と未収集の機器
- **直近の変更**: 新しく保存した世代（機器・変更行数・手動 / スケジュール）と、その世代へのコメント（先頭 60 文字）・確認の状態（確認済み・想定外・未確認。各機器の最初の世代には出しません）。機器名から世代管理を開き、その世代の変更（1 つ前との差分）を表示します
- **次に実行されるスケジュール**: 有効なスケジュールの次回の実行時刻と対象
- 管理者には、システムに異常・注意があるときに「システム状態」への案内を表示します
- **時計**: 見出しの右に現在の日時（例: `2026/11/26（木）11:38`）を 1 分ごと（分が変わった直後）に表示します（秒は出しません）。ブラウザの時計とタイムゾーンで動き（画面のほかの日時と同じ）、サーバーへは問い合わせません。タブを裏に回しているあいだは止まり、戻るとすぐ正しい時刻になります。狭い画面では日付を省きます

1 分ごとに自動で更新します。

## 収集の状態の表示

デバイス管理の各機器のカードに、コンフィグ収集の状態を表示します（閲覧者以上）。「一括収集」「このグループを収集」やスケジュールで収集を始めたあと、どこまで進んだかをこの画面で確認できます。

| 表示 | 意味 |
|---|---|
| ⏳ 収集待ち | 収集を依頼し、順番を待っている |
| 収集中… ○ 秒 | 機器に接続して収集している（経過時間つき） |
| ↻ 再試行待ち | 一時的な失敗（接続のタイムアウトなど）のため、少し待ってからやり直す |
| ✓ 収集 月/日 時:分 | 最後の収集は成功した |
| ✗ 収集失敗 月/日 時:分 | 最後の収集は失敗した（カーソルを合わせると理由を表示） |
| 未収集 | 一度も収集していない |

- 収集が動いている間は一覧の上に「収集中 ○ 台・待ち ○ 台」を表示し、すべて終わると「収集が終わりました（成功 ○ 台・失敗 ○ 台）」と知らせます
- 画面は、収集が動いている間は約 2.5 秒ごと、何も動いていないときは 15 秒ごとに状態を読み直します（スケジュールやほかの人が始めた収集も表示されます）
- 「収集待ち」が長く続くときは、収集を実行する worker が止まっている可能性があります。「システム状態」で確認してください（「待ち」の表示は 30 分で消えます）

## 機器台帳の自動取得

コンフィグを収集するときに、同じ SSH セッションで機種ごとの表示コマンドを実行し、**モデル・シリアル番号・OS バージョン・機器側のホスト名**を読み取ってデバイス管理に表示します（手で入力する必要はありません）。

| 機種 | 実行するコマンド |
|---|---|
| Cisco IOS / IOS-XE / NX-OS / ASA、Arista EOS | `show version` |
| Juniper JunOS | `show version`、`show chassis hardware` |
| Fortinet FortiGate | `get system status` |
| Palo Alto PAN-OS | `show system info` |
| Allied Telesis AlliedWare Plus | `show system` |
| Yamaha RTX | `show environment` |

- 読み取り専用のコマンドだけを、コンフィグを取得し終えたあとに実行します。台帳の取得に失敗しても収集は成功として扱い、前回の値を残します（応答待ちは最長 `INVENTORY_TIMEOUT` 秒、既定 30 秒）
- 上の表に無い機種では何も実行しません（対応の追加は `backend/app/services/inventory.py` の `SPECS`）
- **OS バージョン・シリアル番号・モデルが前回と変わると、アクティビティに「機器情報の変化」として残します**（バージョンアップの記録。シリアル番号・モデルの変化は機器の交換か登録先の取り違えなので警告）。通知設定で「機器情報の変化」を選んだ通知先へも送ります
- デバイス管理の「台帳 CSV」で、機器の一覧（グループ・機種・モデル・シリアル番号・OS バージョンなど。認証情報は含めません）を出力できます。見出しは CSV 一括登録とそろえてあります（「ユーザー名」「パスワード」の列を足せば取り込めます）。検索欄はモデル・シリアル番号でも絞り込めます
- 機器に追加のコマンドを送りたくない場合は `.env` に `INVENTORY_ENABLED=false`（変更後は `setup.sh`）
- FortiGate の VDOM 構成・スタック構成の 2 台目以降・実機ごとの出力の違いには未対応の場合があります。読み取れない項目は空欄になります

## 保存し忘れの検出（startup-config と running-config の不一致）

running-config を変えても startup-config に保存（`write memory` / `copy running-config startup-config`）し忘れると、機器の再起動で変更が消えます。コンフィグを収集するときに、同じ SSH セッションで `show startup-config` も読み、running-config と比べて「保存し忘れ」を見つけます。

| 機種 | 実行するコマンド |
|---|---|
| Cisco IOS / IOS-XE / NX-OS、Arista EOS、Allied Telesis AlliedWare Plus | `show startup-config`（`show running-config` の取得と台帳の取得のあとに実行） |

- **実機では未確認です**。実機が手元に無いため、テスト用の模擬の機器（`backend/tests/fake_sshd.py`）の出力と、公開されている出力例をもとにした比較だけを確認しています。機種・OS のバージョンによって startup-config の見出しの行（`Using N out of M bytes` など）や、保存されていないときの応答が違うと、「比べられない」（不明）や偽の「未保存」になることがあります。そのときは `backend/app/services/startup_check.py` の `COMPARE_IGNORE` に行を足してください
- **状態**: 一致（`synced`）/ 未保存（`unsaved`。running にだけある変更がある）/ 不明（`unknown`）/ なし（対象外・無効）。不明は、startup-config が無い・空・読み取りに失敗した（時間切れ・ページャーで止まった・チャネルが閉じた）・行数が少なすぎる（5 行未満、または running の 1 割未満。エラーの文言を startup とみなさないため）ときです。**読み取りに失敗しても収集は成功のままです**。startup の読み取りは `STARTUP_CHECK_TIMEOUT`（既定 30 秒。機器の応答待ち時間が短ければそちら）で打ち切ります。収集そのものが失敗した回は、状態を変えません
- **不明の回は前回の結果を残します**: 比べられなかった回は、状態・行数・差分・日時を**上書きしません**（理由はログにだけ残します）。未保存 → 読み取れない → 未保存 でも通知せず、バッジも消えません。日時は「最後に比べられた日時」のままなので、バッジのツールチップ・差分のモーダルで確認できます。不明を保存するのは、一度も比べられていない機器だけです
- **比べ方**: running と startup の両方に、機種の無視する行と、画面で設定した「無視する行」を同じように当てます（片方だけ消えて偽の不一致にならないように）。そのうえで**比べるときだけ**、running にだけ付く行・startup にだけ付く行（`Building configuration...`・`Current configuration : N bytes`・`Using N out of M bytes`・`! Last configuration change at …`・`! NVRAM config last updated at …`・NX-OS の `!Time: …`・EOS の `! Startup-config last modified at …`・`! device: …`・`! boot system …`・IOS の `Uncompressed configuration from N bytes to M bytes`・`!` だけの行・空行。後ろの 4 種類は実機で未確認の推測です）を除きます。**保存する running のコンフィグ（世代）は、この整形で変わりません**
- **画面**: デバイス管理の機器カードに「未保存」のバッジ（コンフィグの閲覧権限があれば、押すと startup → running の差分をモーダルで表示）。ダッシュボードに「保存されていない変更」のタイル（対象の機種の機器があるときだけ）
- **差分の扱い**: 差分の本文はコンフィグの中身（秘密の値を含みうる）なので、デバイスの一覧（`GET /api/devices/`）には含めず、`GET /api/devices/{id}/startup-diff`（`config:read`）だけで返します。保存する差分は 200 行までで、通知・アクティビティ・監査ログには行数しか入れません
- **通知・記録**: 通知するのは**一致 → 未保存に変わったときだけ**です（通知設定の「保存し忘れ」。**既定は無効**）。初めて比べられた回（状態が空・不明 → 未保存）は、導入直後に未保存の機器の通知がまとめて届かないよう、通知しません。未保存のままの間も通知しません。状態が未保存に変わったときはアクティビティ（`startup.unsaved`）に残し、保存されて一致に戻ったときはアクティビティ（`startup.synced`）だけです
- **既知の制限**: 機種・OS のバージョンによっては、証明書などが running では 16 進の全文、startup では `nvram:xxx.cer` の参照になり、保存済みでも「未保存」と出ることがあります（対処していません）。誤って「未保存」と出続けるときは、画面の「無視する行」でその行を除いてください（running と startup の両方に適用されます）
- 対象の機種は `PlatformSpec.startup_command` で決めます（PAN-OS の候補設定と実行中・FortiGate・Junos は概念が違うため対象外）。対象外の機種・無効のときはコマンドを送らず、状態は空のままです（以前の値があれば消します）
- 機器に追加のコマンドを送りたくない場合は `.env` に `STARTUP_CHECK_ENABLED=false`（変更後は `setup.sh`）。無効・対象外の機種では、画面・API（`startup_*`）にも以前の結果を出しません

## コマンド実行（表示コマンドの一括実行）

メニュー「機器」の「コマンド実行」で、選んだ複数の機器へ **表示コマンド（show / display など、設定を変えないもの）** を一括で送り、機器ごとの出力を見られます。設定を変えるコマンドは送れません。

- **使い方**: 対象の機器（グループを選ぶと、そのグループの有効な機器が選ばれます）を選び、コマンドを 1 行に 1 つ入力して「実行」。進み具合は自動で更新され、終わると結果を「機器ごと」（折りたたみ・コピー）と「同じ出力ごと」（同じ出力の機器をまとめる。比較は行末の空白と末尾の空行を除いた完全一致）で切り替えて見られます。「テキスト保存」「CSV 保存」と、過去の実行（新しい順に 50 件。ほかのユーザーの実行も見えます）の開き直しができます
- **権限**: `command:run`（オペレーター・管理者）。結果の閲覧も同じ権限です（出力に設定の中身が含まれるため、閲覧者には付けません。`CONFIG_READ` を持つロールにだけ付ける決まりで、テストが確かめています）
- **送れるコマンド**（`backend/app/services/command_run.py`。許可リスト方式で、迷うものは拒否します）
  - 1 回に 5 個まで、1 個 200 文字まで。半角の英数字と記号だけ（制御文字・タブ・改行・全角文字は不可）。`?`（ヘルプ）・`;`・`&`・バッククォート・`$`・`~`・`>`・`<`・`\` は不可。`* { } " '` は、シェルを経由する機種（VyOS・EdgeRouter・Check Point Gaia）と、パイプの後ろで本物の grep が動く機種（Arista EOS・NX-OS・Fortinet・NetScaler・Yamaha など）で不可
  - 先頭の語が、その機種で許された読み取りの語であること。**省略形（`sh`・`sho`・`dis` など）を認めるのは、CLI が省略形を解釈すると確かな機種だけ**（Cisco IOS / IOS-XE / IOS-XR / NX-OS / ASA、Arista EOS、Huawei VRP・VRP V8、HPE Comware）です。それ以外の機種は完全一致（`show` など）のみで、省略形は通りません。`conf`・`reload`・`write`・`copy`・`delete`・`clear`・`debug`・`set`・`request` などは先頭の語が違うため通りません
  - シェルに届く機種（VyOS・Ubiquiti EdgeRouter・Check Point Gaia）は、英数字と `_ . : / @ % + = , ^ | -` だけを許し、`-` で始まる語（`sh -c reboot` のようなオプション）は拒否します。`show -c x`・`show file /path` のような形は通りません
  - 機種ごとの違い: Huawei・HPE Comware は `display`（`dis` などの省略形は可）、Fortinet は `get` / `show`、Juniper ScreenOS は `get`、Nokia SR OS は `show` のみ（`admin display-config` などの `admin` 系は不可）。**MikroTik RouterOS は対象外**（メニューや引数の形が多く、許可リストで安全に絞れないため。登録しても実行は「対象外」になり、API は 422）。`tech-support`（`tech`・`techsupport` などの省略形を含む。省略形を認める機種では `tec` 以上の前方一致も）は、出力が巨大で機器への負荷が高いため全機種で不可です。`diagnostic-information`（`diag` 以上の省略形を含む。Huawei・Comware ではファイル名を付けると機器内へ書き出せる）も全機種で不可です
  - パイプ（`|`）の後ろは、その機種で使える絞り込みだけで、引数の形も決まっています（引数はちょうど 1 個。`-` で始まる・`/` や `:` を含むものは不可。`count`・`no-more` など引数なしの語には付けられず、`last`・`head`・`tail` は数字 1 個）。`redirect`・`tee`・`append`・`save`・`file`・`copy`・`tftp` などは拒否します。`|` はすべて区切りとして扱うため、正規表現の `a|b` は使えません（コマンドを分けてください）。絞り込み語の短縮（`i`・`in` → `include`、`e`・`ex` → `exclude`、`b`・`be` → `begin`、`sec` → `section`）は、Cisco IOS / IOS-XE / IOS-XR / ASA、Huawei VRP・VRP V8、HPE Comware だけです（NX-OS・Arista EOS は完全一致のみ）

    | 機種 | 使える絞り込み（引数） |
    |---|---|
    | Cisco IOS / IOS-XE / IOS-XR / ASA、Huawei、HPE Comware | `include` / `exclude` / `begin` / `section`（1 個）、`count`（なし）など機種の語 |
    | Cisco NX-OS | 上記 + `grep` / `egrep`（1 個）、`last` / `head` / `tail`（数字）、`no-more` / `json` / `json-pretty` / `xml` / `wc`（なし） |
    | Arista EOS | Cisco 系 + `grep` / `egrep`（1 個）、`json` / `no-more`（なし） |
    | Juniper Junos | `match` / `except` / `find`（1 個）、`count` / `no-more`（なし）、`last` / `trim`（数字）、`display`（`set` / `xml` / `json` / `detail` / `inheritance` / `omit` / `changed` から 1 個） |
    | Palo Alto PAN-OS | `match` / `except`（1 個）、`last`（数字） |
    | Fortinet / NetScaler | `grep`（1 個） |
    | Yamaha | `grep` / `include` / `exclude`（1 個） |
    | VyOS・Ubiquiti EdgeRouter | `match`（1 個）、`no-more` / `count`（なし） |
    | Check Point Gaia | パイプは使えません |

    通らない例: `show x | include Gi|Te`（コマンドを分ける）、`show x | grep x /etc/shadow`（引数は 1 個）、`show x | grep --file=bootflash:a x`、`show x | match -f /config/config.boot`（`-` で始まる・`/` や `:` を含む）、`admin display-config`（Nokia）、`show tech-support`、MikroTik の `/ip address print`
  - enable・設定モードに入るコマンドは送りません。接続時の特権モードへの移行は、収集と同じ既存の仕組み（Enable パスワードを設定した機器だけ）のままです
  - 検証は、実行を作る前（API。入力中は `GET /api/commands/check` で理由を表示）と、worker が機器へ接続する直前（もう一度。キューの値も信用せず、機器の今の機種で検証し直す）の 2 回です。理由は日本語で返し、API は 422 です
  - 機種が違う機器をまとめて選んだときは機器ごとに検証し、送れない機器は「対象外」として結果に残します（すべての機器に送れないときは 422）。無効な機器・実行までに削除された機器も「対象外」です
- **出力の扱い**: 機器ごとの出力は `DEVICE_ENCRYPTION_KEY` で暗号化して DB に保存し（`command_results.outputs`）、`COMMAND_RUN_RETENTION_DAYS`（既定 30 日）を過ぎた実行は毎日の掃除（`purge_audit_logs`）で出力ごと削除します。`DEVICE_ENCRYPTION_KEY` を変えると過去の出力は読めなくなります。1 コマンドの出力は `COMMAND_RUN_MAX_OUTPUT`（既定 20 万文字）、1 回の実行の合計は `COMMAND_RUN_MAX_RUN_OUTPUT`（既定 2,000 万文字）で切り捨て、切ったことを画面に出します。止まった機器（worker の停止など）は、5 分ごとの定期タスク（`fail_stale_command_runs`）が失敗にして実行を終わらせます。判断は実行の作成時刻ではなく機器ごとの時刻で行い、実行中のまま 2 時間たった機器、または実行中の機器が無く 60 分以上動きのない実行の待機中の機器が対象です（収集などでキューが詰まると、待機中のまま 60 分たった機器は失敗になります）。実行中・待機中の機器が 1 台も無いのに終了時刻が空の実行も、同じタスクが終わらせます（実行数の上限の枠を占め続けないため）
- 出力の先頭・末尾の空行（空白だけの行）は、保存するときに取り除きます（中の空行・最初と最後の行のインデントは残します）。1 コマンドの上限・実行全体の枠・「切り捨て」の判定は、取り除いたあとの文字数で行います。「同じ出力ごと」のまとめは、末尾の空行・行末の空白・CRLF を無視する従来どおりの比較です
- **実行の仕組み**: 機器 1 台ごとに worker のタスク（`run_command_device`）を投入し、収集と同じ機器ごとの SSH ロックを使います（収集・FW ヒット数の取得と重なったときは最大 5 分待ちます）。1 回の実行の中で同時に接続するのは `COMMAND_RUN_CONCURRENCY`（既定 10）台までで、残りは待ち行列（Redis）に置き、終わるたびに次を投入します。失敗しても再試行しません（同じコマンドを何度も機器へ送らないため）。ページャー（`--More--`）の検出・応答待ちの時間切れは収集と同じです。worker の処理中に想定外の例外が起きても、その機器を「内部エラー」の失敗にして（出力は残さない）、必ず次の機器を投入します
- **上限・設定**（`.env`。変更後は `setup.sh`）: `COMMAND_RUN_ENABLED`（`false` で新しい実行を受け付けない。過去の結果は見られます）、`COMMAND_RUN_MAX_DEVICES`（1 回の対象の機器数。既定 100）、`COMMAND_RUN_CONCURRENCY`、`COMMAND_RUN_MAX_ACTIVE_PER_USER`（1 人が動かせる未完了の実行の数。既定 2）、`COMMAND_RUN_MAX_ACTIVE`（全体の未完了の実行の数。既定 5。超えると 429 で、動いている件数を日本語で返します）、`COMMAND_RUN_MAX_OUTPUT`、`COMMAND_RUN_MAX_RUN_OUTPUT`、`COMMAND_RUN_RETENTION_DAYS`
- **API**（すべて `command:run`）: `GET /api/commands/limits`（上限・機種ごとの先頭の語）、`GET /api/commands/check`（入力中の検証）、`POST /api/commands/runs`（`device_ids` か `group_id` と `commands`）、`GET /api/commands/runs`、`GET /api/commands/runs/{id}`（機器ごとの状態と出力・`groups`＝コマンドごとの同じ出力のまとめ。出力の本文は繰り返さず、代表の結果の `result_id` で `results` を参照します。`outputs=false` で出力を省く）、`GET /api/commands/runs/{id}/export?format=txt|csv`
- **監査ログ**: 実行（`command.run`: 誰が・どの機器に（20 台まで）・どのコマンドを・台数・対象外の数）と書き出し（`command.export`）を残します。**出力は監査ログに入れません**
- **対象の機器**: 閲覧できる権限（`device:read`）があれば全機器が対象です（機器やグループ単位の権限の仕組みは、まだありません）
- 範囲外（今後の拡張ポイント）: スケジュール実行、設定の投入、時刻などの毎回変わる部分を除いたまとめ、踏み台の先の機器の特別扱い（既存の接続の仕組みで届くものは届きます）

## コンフィグ検索

全機器の**最後に収集したコンフィグ**（選べば過去の世代も）を横断して検索します（閲覧者以上）。「この IP アドレス・VLAN・ACL はどの機器にあるか」「この設定が入っていない機器はどれか」を調べるための画面です。

- **探し方**: 文字列を含む（記号もそのまま探す）/ 正規表現。大文字と小文字は既定で区別しません
- **絞り込み**: 機器グループ・機種（メーカーごとにまとめて表示）
- **結果**: 機器ごとに、一致した行（行番号つき、一致箇所を強調）と、必要なら前後 1〜3 行。機器ごとの表示は 50 行までで、件数はすべて数えます。「世代管理で開く」からその機器の履歴へ移動できます
- **一致しなかった機器**: 収集済みで一致する行が無かった機器の一覧。未収集の機器は別に表示します
- **CSV 出力**: 検索結果の「CSV 出力」で、直前に検索した条件で一致した行を**すべて**（画面の 50 行の制限とは別）CSV にします。列は 機器名・ホスト / IP・機種・グループ・世代（コミットの先頭 7 桁）・行番号・一致した行（機器名順）
  - 上限は合計 10 万行、時間の制限は検索と同じです。上限で打ち切ったときや、時間内に調べきれなかった機器があるときは画面で知らせます。前後の行は含めず、長い行は画面と同じく 400 文字で切ります
  - Excel でそのまま開けるよう BOM 付き UTF-8。`=` `+` `-` `@` で始まる行は、数式として実行されないよう先頭に `'` を付けます
  - 出力したこと（件数と絞り込み条件）は監査ログに「コンフィグ検索結果の CSV 出力」として残りますが、検索語は残しません
- **過去の世代も含める**: 「対象の世代」で選ぶと、各機器の世代を新しい順にさかのぼって探します。「この IP はいつから入っているか」「消した設定がいつまであったか」を調べるためのものです
  - 一致した行は内容ごとにまとめ、**いまもある**（最新の世代にある）か**消えた**か、**最初に見つかった世代**と（消えた行は）**最後にあった世代**の日時を表示します。日時から世代管理のその世代を開けます。いまもある行を先に、消えた行は消えたのが新しい順に並べます
  - 期間（から・まで。サーバーの `TIMEZONE` の日付）で絞れます。期間で最新の世代が外れても、「いまもあるか」は最新の世代で判定します
  - 調べる世代は機器ごとに新しい 500 世代まで、全体の時間は 30 秒までです。古い世代まで調べきれなかった機器は画面に表示します（その機器の「最初に見つかった世代」はそれより前のことがあります）。同じ内容の世代は 1 回だけ調べます。前後の行は表示しません
  - CSV の列は 機器名・ホスト / IP・機種・グループ・いまもある・最初に見つかった世代とその日時・最後に見つかった世代とその日時・一致した行
- 正規表現の照合は機器ごとに `COMPLIANCE_REGEX_TIMEOUT` 秒、全体で 15 秒（過去の世代も含めるときは 30 秒）までに制限し、調べきれなかった機器は画面に表示します
- 正規表現の検索語は、読み込みが重いものを受け付けません（422。「セキュリティ」の「利用者が入力する正規表現の制限」）。重さの確認も同時に実行できる検索の数に含めます。文字列の検索は確かめません（エスケープして使うため）
- 同時に実行できる検索（CSV 出力も含む）は、1 人 `SEARCH_MAX_PER_USER` 件（既定 2）・全体 `SEARCH_MAX_CONCURRENT` 件（既定 4）までです。超えると待たずに「前の検索が終わるまでお待ちください」と表示します（検索の連打や複数のタブで、ほかの人のログインや画面の操作が遅くならないように）
- 検索語はアクセスログ（URL）に残しません（検索も CSV 出力も、条件は URL ではなく本文で送ります）

## 外部 Git への push（GitLab / Gitea）

コンフィグ履歴を、社内の GitLab / Gitea などへも送ります。サーバーの外にも履歴が残り、Git サーバーの画面で差分やコンフィグを見たり、ほかの仕組みから参照したりできます。`.env` の `GIT_EXPORT_URL` を設定したときだけ動きます。

- **送る内容**: 書き出し用のリポジトリ（`GIT_REPO_PATH/_export`）を 1 つ作り、各機器の最新コンフィグを `グループ名/機器名.txt`（グループなしは `未分類/`）として置き、`README.md` に機器の一覧（ホスト・機種・最後に変わった日時）を書きます。未収集の機器は含めません。機器の削除・改名・グループの変更はファイルの削除・移動になります
- **いつ送るか**: 収集でコンフィグが変わったら `GIT_EXPORT_DELAY_SEC` 秒（既定 60 秒）後に 1 回（その間に一括収集で何台変わっても 1 コミット）。送り損ね（相手が止まっていた等）に備えて 1 時間ごとにも確認し、未送信があれば送ります。管理者は「システム状態」の「今すぐ push」でも実行できます（監査ログに残ります）
- **コミット**: メッセージに変わった機器の名前を書きます（例「コンフィグの更新: Core-SW01、SW-2F」）。作者は `GIT_EXPORT_AUTHOR`
- **相手のリポジトリ**: 空のリポジトリを作っておきます。ブランチは `GIT_EXPORT_BRANCH`（既定 main）。**相手のブランチを直接変更しないでください**（こちらに無いコミットがあると push を拒否され、失敗として通知します）。強制 push はしません
- **認証（HTTPS）**: `GIT_EXPORT_USERNAME` と `GIT_EXPORT_TOKEN`（GitLab ならプロジェクトアクセストークン・権限 write_repository。ユーザー名は空のままで可、Gitea ならユーザー名とアクセストークン）。トークンは push のときだけ環境変数で git に渡し、URL や `.git/config` には書きません。URL に認証情報（`https://user:token@...`）を書いても動きますが、`.git/config` には除いた URL を保存し、画面・調査用ログ（`collect_logs.sh`）では伏せ、「システム状態」で `GIT_EXPORT_USERNAME` / `GIT_EXPORT_TOKEN` へ移すよう注意を出します
  - 社内の CA の証明書なら `GIT_EXPORT_CA_FILE` に CA 証明書のコンテナ内のパスを指定します（例: `/data/ssh/git-ca.crt` に置く）
- **プロキシ（インターネット上の Git へ出すとき）**: `https://` の宛先が「外部への接続」のプロキシの対象（`OUTBOUND_PROXY` があり、`OUTBOUND_NO_PROXY`・内向きに当たらない）なら、`OUTBOUND_PROXY` を git のプロセスの環境変数（`https_proxy`）だけで渡します。コマンドラインの引数・`.git/config` には書きません。対象でない宛先では、プロキシの環境変数を空にして渡します（コンテナの環境の値は使いません）。失敗の文の中のプロキシの URL・認証情報は伏せます
  - プロキシを設定すると、`OUTBOUND_NO_PROXY` に入れていない **社内の `https://` の Git サーバー** への push もプロキシへ向かいます。社内の Git サーバーは `OUTBOUND_NO_PROXY` に入れてください
  - `GIT_EXPORT_TOKEN` は宛先の Git サーバーの問いにだけ答え、プロキシの認証の問いには答えません（プロキシへトークンを送らない）
  - SSH の宛先（`git@host:path`・`ssh://`）は HTTP のプロキシを通せないので、今までどおり直接つなぎます。平文の `http://` の宛先は、プロキシ経由では接続しません（`https://` にするか `OUTBOUND_NO_PROXY` に入れてください）
  - `OUTBOUND_CA_FILE`（HTTPS を検査するプロキシの CA）があれば、`https://` の宛先で使います。`GIT_EXPORT_CA_FILE` が無いときは OS の信頼と束ねたものを、あるときは `GIT_EXPORT_CA_FILE` と束ねたものを使います（`GIT_EXPORT_CA_FILE` があるときは、今までどおり OS の信頼は使いません）。束ねたファイルは push の間だけの一時ファイルです
- **認証（SSH）**: `GIT_EXPORT_URL=git@gitea.local:net/configs.git` と `GIT_EXPORT_SSH_KEY=/data/ssh/git_export_key`。鍵は worker コンテナの `/data/ssh`（ssh_data ボリューム）に置きます
  ```bash
  ssh-keygen -t ed25519 -N "" -f git_export_key   # 公開鍵（.pub）を相手のデプロイキーに登録（書き込みを許可）
  sudo podman cp git_export_key netconfig-manager_worker_1:/data/ssh/git_export_key   # コンテナ名は podman ps で確認
  sudo podman exec netconfig-manager_worker_1 chmod 600 /data/ssh/git_export_key
  ```
  相手のホスト鍵は初回の接続で `/data/ssh/git_known_hosts` に記録し、以後は変わったら接続しません
- **結果**: 「システム状態」の「外部 Git への push」に最後の結果を表示します。失敗は「システムの異常」として通知し、アクティビティにも残します（同じ失敗が続く間は繰り返しません）。成功するとアクティビティに「外部 Git への push」を残します
- 機器ごとの履歴（世代管理の画面）とは別のリポジトリなので、外部へ送っていない過去の世代は含みません（設定した時点の最新から始まります）

## 外部への接続（プロキシ・組織の CA）

直接インターネットへ出られない環境で、アプリ（backend・worker）からインターネットへの HTTPS を、`.env` の 1 か所の設定でプロキシに通し、HTTPS の中身を検査するプロキシの CA（例: Example Corp CA）を信頼させます。設定しなければ、今までどおり直接つなぎます。導入・更新（`setup.sh` の git・パッケージ・イメージの取得）のプロキシは「自動セットアップ」の節を参照してください。

### 対象の通信

| 通信 | プロキシ（`OUTBOUND_*`） |
|---|---|
| Discord・Slack・Teams の Webhook | 通す |
| メールの OAuth 2.0 のトークンの取得（Microsoft 365・Google） | 通す |
| 脆弱性情報・サポート終了日の取得（`VULN_ENABLED=true` のとき） | 通す |
| システム状態の「接続を確かめる」（固定の宛先 `endoflife.date`） | 通す |
| メールの送信そのもの（SMTP） | **通さない**（HTTP のプロキシは通常 SMTP を通しません） |
| 外部 Git への push（`GIT_EXPORT_URL` が `https://` のとき。「外部 Git への push」を参照） | 通す（git に環境変数で渡す。SSH の宛先は直接） |
| 機器への SSH・踏み台・SNMP・Ping、DB・Redis、HTTPS の証明書の期限の確認 | 通さない（内向き・HTTP 以外） |

### 設定（`.env`。変えたら `setup.sh` でコンテナを作り直す）

| 設定 | 内容 |
|---|---|
| `OUTBOUND_PROXY` | `http://ホスト:ポート`、認証が要るなら `http://ユーザー:パスワード@ホスト:ポート`（例: `http://proxy.example.test:3128`）。**`http://` だけ**で、**ポートは必須**です（`https://`・SOCKS のプロキシ・ポートの無い値・不正な値は起動時にエラー。値はエラーに出しません）。ユーザー名・パスワードの記号は URL エンコードで書きます（`@` → `%40`、`:` → `%3A`、`%` → `%25`、`#` → `%23`、`/` → `%2F`。例: パスワード `p@ss:word` → `http://user01:p%40ss%3Aword@proxy.example.test:8080`）。**ユーザー名だけ（`http://user01@…`）は起動時にエラー**です（git などがパスワードを聞き返し、ほかの秘密を答えてしまうおそれがあるため）。パスワードが空なら `http://user01:@proxy.example.test:8080` と書きます |
| `OUTBOUND_NO_PROXY` | プロキシを通さない宛先（カンマ区切り）。書けるのは **ホスト名・ドメイン（`example.test`・`.example.test`・`*.example.test` はどれも同じ扱いで、そのドメインと配下）・IP・CIDR** と、すべてを直接にする `*` だけです。ポートつき（`host:8080`）・途中に `*` を含む書き方・日本語のドメイン（punycode の `xn--…` で書く）は起動時にエラーです。`localhost`・ループバック・コンテナ名（`db`・`redis`・`backend` など）は書かなくても直接つなぎます |
| `OUTBOUND_CA_FILE` | 追加で信頼する CA 証明書（PEM。複数をつなげてもよい）のファイルの名前。ファイルはサーバーの `certs-outbound/`（例: `/opt/netconfig-manager/certs-outbound/outbound-ca.pem`）に置き、`.env` には `outbound-ca.pem` のように名前だけを書きます。コンテナの中では `/etc/netconfig/outbound/` に読み取り専用で見えます。読めない・PEM でない・証明書が無い・秘密鍵が入っているときは起動時にエラーです |

- **環境変数の `HTTPS_PROXY`・`NO_PROXY` などは見ません**（設定の出どころを `.env` の 3 つにまとめるため）
- HTTPS の宛先へは CONNECT のトンネルで通し、宛先との TLS はトンネルの中で張ります。証明書とホスト名の検証は弱めません（追加の CA は OS の既定の信頼に **足す** だけ。検証を切る設定はありません）。組織の CA を入れても、名前の違う証明書は拒否します
- プロキシの認証は Basic（`Proxy-Authorization`）で、CONNECT にだけ付けます（宛先へのリクエストには付けません）
- 平文（`http://`）の宛先には、プロキシ経由では接続しません（外部へは HTTPS だけ。平文の宛先へのリクエストにプロキシの認証情報を付けて送ることはしません）
- `certs/`（nginx のサーバー証明書と秘密鍵）とは別のディレクトリです（backend に秘密鍵を見せないため）
- 失敗は分かる文にします: 「プロキシに接続できません」「プロキシの認証に失敗しました（HTTP 407）」「プロキシが接続を断りました（HTTP 403 など）」「証明書を検証できません（HTTPS を検査するプロキシなら、組織の CA を OUTBOUND_CA_FILE に指定してください）」「時間切れ」。どの文・ログ・画面・監査ログにも、プロキシのユーザー名・パスワード・`Proxy-Authorization` の値は出しません（画面に出すのはホスト:ポートと「認証あり／なし」だけ）
- 起動時に backend・worker のログへ 1 行（例: `外部への接続: プロキシ proxy.example.test:3128（認証あり）・追加の CA 1 件`）出します

### 確かめる（システム状態の「外部への接続」）

プロキシの有無（ホスト:ポートと認証の有無）、プロキシを通さない宛先、追加の CA の件数といちばん近い有効期限（期限切れ・30 日以内は注意）を表示します。管理者は **「接続を確かめる」** で、固定の宛先（`https://endoflife.date/`。利用者は宛先を選べません）へ HEAD を送り、結果（成功／プロキシに接続できない／プロキシの認証に失敗／証明書を検証できない／時間切れ など）を確かめられます。宛先から HTTP の応答が返れば成功です（プロキシが宛先を許可していないと「プロキシが接続を断りました」になります）。30 秒に 1 回まで、操作は監査ログ（「外部への接続の確認」。結果の種類だけ）に残ります。API トークンでは使えません（ログインして操作）。

### 限界

- SMTP（メールの送信そのもの）はプロキシを通しません。要望があれば別に対応します
- SOCKS・`https://` のプロキシ・NTLM / Kerberos の認証には対応しません（Basic 認証だけ）
- **プロキシまでの区間は暗号化されないため、認証情報（Basic 認証）が平文で流れます**。信頼できる社内の経路でだけ使ってください（宛先との通信はトンネルの中の TLS で保護されます）
- 3 文字未満のパスワードは、伏せ字の対象にしません（短い文字列を伏せると文が読めなくなるため。エラーの文は種類ごとの決まった文にしているので、通常は出ません）。ユーザー名は普通の語でありうるので、`ユーザー名:`・`ユーザー名@` の形のときだけ伏せます
- OS（サーバー本体）の信頼ストアへの CA の登録は、`setup.sh` の節の案内に従って利用者が行います
- backend のイメージには、ビルドのときに組織の CA が OS の信頼として入ります。そのため外向きの HTTPS 以外（SMTP の TLS・外部 Git など、OS の信頼を使う通信）でも、その CA で署名された証明書を信頼します

## システム状態（止まっていることに気づく）

API が応答していても、worker やスケジューラーが止まっているとコンフィグ収集は動きません。収集の失敗の通知は「収集して失敗した」ときにしか飛ばないため、**動いていないこと自体**を検出して知らせます。

### 画面（メニュー「管理」の「システム状態」。管理者のみ）

| 項目 | 見ているもの | 異常のとき |
|---|---|---|
| データベース・Redis | 接続できるか | 画面・収集が動かない |
| worker | 指示に応答するか | 収集・通知・コンプライアンスチェックが実行されない |
| スケジューラー（beat） | 毎分の定期実行（heartbeat）が届いているか | スケジュール収集が始まらない |
| スケジュール | 有効な件数・最後に実行した時刻 | （表示のみ） |
| 収集の状況 | `SYSTEM_STALE_DAYS`（既定 7 日）以上収集できていない有効な機器 | 注意として機器名を表示 |
| ディスクの空き | コンフィグ履歴・ターミナルの記録の保存先（15% 未満で注意、5% 未満で異常） | 収集結果を保存できなくなる |
| HTTPS の証明書 | 期限（30 日以内で注意、7 日以内で異常） | 画面を開けなくなる |
| バックアップ | `scripts/backup.sh` の最後の結果（最後の成功の日時・保存先・サイズ・外部コピーの結果）。失敗で異常、外部への保管の失敗・`BACKUP_STALE_HOURS`（既定 36 時間）以上成功していないときは注意 | サーバーが壊れたときに戻せない |
| 外部 Git への push | 設定したとき（`GIT_EXPORT_URL`）だけ。最後の push の結果。失敗で異常（「今すぐ push」で再実行） | GitLab / Gitea のコンフィグが古いまま |
| メール送信 | メール送信を有効にしたときだけ。設定の不足と、最後の送信の結果。失敗で異常 | メールの通知が届かない |
| 脆弱性情報の取得 | `VULN_ENABLED=true` のときだけ。情報源ごとの最後の成功・失敗の理由。失敗している情報源があるか、3 日以上取得できていないときは注意（通知はしません） | 脆弱性・サポート終了日が古いまま |
| 外部への接続 | プロキシ（ホスト:ポートと認証の有無だけ）・プロキシを通さない宛先・追加の CA の件数と期限・最後の「接続を確かめる」の結果。CA の期限切れ・30 日以内、確認の失敗は注意（通知はしません）。何も設定していなければ「—」（直接） | Webhook・メールの OAuth・脆弱性情報の取得が外へ出られない |
| コンテナのイメージ | `setup.sh` が伝えた PostgreSQL・Redis・ビルドの土台のイメージの作成日時。`IMAGE_STALE_DAYS`（既定 60 日、0 で確認しない）より古い・取り直せなかったときは注意 | セキュリティ修正が入っていない |

注意・異常があるときは、管理者のメニュー「管理」の「システム状態」に印（黄・赤）が付きます（「管理」を閉じているときは「管理」の見出しに付きます）。

**表示する項目の選択**: 「再確認」の横の「項目」メニューに全項目の状態を一覧で表示します。項目を選ぶとその詳細を表示し、＋ で画面に大きく（カードで）表示、− で画面から外します。

- 選んだ内容はブラウザに保存します（ユーザーごと。別のブラウザ・PC では最初はすべて表示）。「すべて表示」で元に戻ります
- 画面から外した項目も監視・通知は続け、「要確認 ○ 件」にも数えます。外した項目が注意・異常になったときは画面の上に知らせ、押すと画面に戻します

### 通知

通知設定の「通知する内容」で **システムの異常**（既定で有効）を選んだ通知先（Discord / Slack / Teams / メール）へ送ります。機器に結び付かないため、対象の機器グループに関係なく届きます。

- worker・スケジューラー・Redis の停止は、`SYSTEM_ALERT_AFTER_MIN` 分（既定 10 分）続いたときに通知します（更新・再起動中の一時的な停止では通知しません）
- 長期間収集できていない機器・ディスク・証明書は、見つけたとき（機器は増えたとき、ほかは悪化したとき）に通知します
- 同じ異常を繰り返し通知することはなく、復旧したときにもう一度通知します。発生と復旧はアクティビティ（システム）にも残ります
- 確認は API のコンテナ（backend）が行うため、worker・スケジューラーが止まっていても通知できます。backend 自体やサーバーが止まった場合は通知できません（外部からの死活監視には `/api/health` を使ってください）
- 収集しない機器が警告に出る場合は、その機器を「無効」にするか、`SYSTEM_STALE_DAYS=0` で確認を止めます。通知全体を止めるには `SYSTEM_WATCHDOG_ENABLED=false`
- バックアップは、失敗するたびに（続けて失敗しても毎回）通知します。結果の記録が一度も無い環境（バックアップを使っていない・開発環境）では確認しません。ただし `setup.sh` でタイマーを登録したのに `BACKUP_STALE_HOURS` を過ぎても結果が届かないときは注意にします。`BACKUP_ON_CALENDAR` を週 1 回などにした場合は `BACKUP_STALE_HOURS` を間隔より長く（例: 192）し、確認しない場合は 0 にします

### 更新後の自動確認

`scripts/setup.sh` は、起動確認のあとに `python -m app.tools.selfcheck` を backend のコンテナで実行します。タスクを登録して worker が実行するか、スケジューラーからの定期実行が届くかまで確かめ、失敗した場合は worker・beat のログを表示して異常終了します（更新直後に「収集が動かない」状態に気づけます）。手動で確かめるときは `sudo podman exec <backend のコンテナ> python -m app.tools.selfcheck`。


## 調査用のログをまとめる（起動しない・動きがおかしいとき）

エラーで起動しない、収集が動かない、画面が開かないなどのときに、原因を調べるための情報を 1 つのファイルにまとめます。コンテナが止まっていても、Podman が動いていなくても、集められるものだけを集めて最後まで進みます。

```bash
bash /opt/netconfig-manager/scripts/collect_logs.sh
```

`/var/tmp/netconfig-logs/netconfig-logs-<日時>.tar.gz` ができ、大きさと、集められなかったものを表示します。

| オプション | 意味 |
|---|---|
| `--days 7` | さかのぼる日数（既定 3 日） |
| `--lines 20000` | コンテナごとのログの行数の上限（既定 5000 行。新しいものから） |
| `--full` | 行数の上限なし（期間の指定は有効。大きくなることがあります） |
| `--out /tmp` | 保存先（既定 `/var/tmp/netconfig-logs`） |
| `--keep 5` | 保存先に残す数（既定 5。古いものから消します） |

- **集めるもの**: アプリの版と Git の状態、OS・Podman の版、ディスク・メモリの空き、コンテナの一覧と状態（終了コード・再起動の回数・メモリ不足で止まったか）、コンテナごとのログ、設定（`.env`。秘密の値は伏せます）、起動確認（`/api/health`・自己診断）、DB のマイグレーションの版、アプリが記録した直近の警告・エラー、systemd の状態とログ、ファイアウォール、待ち受けポート、SELinux の拒否（Ubuntu は AppArmor の状態と拒否）、メモリ不足（OOM）の記録、証明書の期限、最後のバックアップの結果
- **集めないもの**: 機器のコンフィグ、DB の中身、ターミナルの記録、`.env` の秘密の値、証明書の秘密鍵
- **大きさを抑える工夫**: ログは期間（既定 3 日）と行数（コンテナごとに 5000 行）で絞り、テキストを gzip（最高の圧縮率）でまとめます。通常は数百 KB〜数 MB です。50 MB を超えたときは、絞り込みを案内します
- **伏せるもの**: `.env` のパスワード・暗号化キー・トークン・Webhook の URL・接続先 URL、ログの中の Webhook の URL・URL に埋め込んだパスワード・`password=` などの値・トークンらしい文字列
  - プロキシ: `.env` の `OUTBOUND_PROXY`（と廃止した `VULN_HTTPS_PROXY`）は、認証情報だけを伏せて host:port は残します（`http://***@proxy.example.test:3128`。認証なしならそのまま。起動時のログ・「システム状態」の表示と同じで、切り分けに使えます）。`OUTBOUND_NO_PROXY` は件数だけ、`OUTBOUND_CA_FILE`（ファイル名）はそのまま。ログの中の `http_proxy=`・`https_proxy=` の認証情報も伏せます。`certs-outbound/` の CA の subject・発行者・期限は `app/outbound-ca-*.txt` に入れます
- **注意**: 機器名・IP アドレス・ユーザー名は含まれます。外部へ渡す前に、展開して中身を確かめてください（`tar -xzf <ファイル> -C /tmp`。中身はテキストです）。ファイルは実行した人だけが読める権限（600）で作ります
- **まず見る場所**: `summary.txt`（概要と集められなかったもの）→ `containers/*.state.txt`（止まった理由）→ `containers/*.log`

## アクティビティ（システムで起きたことの記録）

「アクティビティ」画面で、システムで起きた出来事を確認できます（閲覧者以上）。利用者の操作は「監査ログ」、処理の結果・出来事はこちら、と分けています。

| 種類 | 記録する出来事 |
|---|---|
| 収集 | 変更あり（+n / -n 行・世代）／変更なし／初回取得／失敗（再試行する場合は警告、最終的な失敗はエラー）／実行中のためスキップ／一括収集の開始 |
| スケジュール | スケジュールの実行（種類・対象）、Cron 式が不正で実行できないとき（1時間に1回まで） |
| 無視する行 | ルールを適用できず、その回のコンフィグを保存しなかったとき（照合の時間切れ `ignore.timeout`／不正な正規表現・読み込みが重すぎる `ignore.skipped`／重さを確かめられない `ignore.unavailable`。機器・正規表現・理由）、追加のルールで全行の 50% 以上が消えたとき（`ignore.broad`。保存は続ける） |
| コンプライアンス | 違反の発生・解消・例外による除外・例外の期限切れ（機器・ルール・重要度・該当箇所）、スケジュールでの検査の結果（台数・新しい違反・解消の件数）。ルールの追加などで一度に 30 件を超えて変わったときは1件にまとめる |
| 通知 | 変更・違反・収集失敗の通知の送信と失敗（送信先の種類と誰の設定か。URL は残さない） |
| システム | 保持期間を過ぎたログの削除、システムの異常と復旧 |
| バックアップ | バックアップの完了（ファイル名・保存先・外部へのコピー先）・失敗（どこで失敗したか）・外部への保管の失敗 |

- 「きっかけ」には、手動の収集なら実行したユーザー名、スケジュールなら「スケジュール「名前」」、自動処理なら「システム」を記録します
- 種類・重要度（情報・警告・エラー）・機器・キーワード・期間で絞り込めます。行をクリックすると詳細（世代へのリンク・違反箇所など）を表示します
- 監査ログの「収集の実行」の行にある「収集の結果を見る」から、その実行の結果（各機器の収集・違反・通知）だけを表示できます（一括収集・スケジュールは配下の機器の記録をまとめて表示）
- 「CSV 出力」で、今の絞り込み条件のまま CSV に書き出せます（形式は監査ログの CSV 出力と同じ。出力したことは監査ログに残ります）
- 保持期間は `.env` の `ACTIVITY_LOG_RETENTION_DAYS`（既定 90 日、0 で無期限）。スケジュール収集の「変更なし」で件数が増えるため、不要なら `ACTIVITY_LOG_UNCHANGED=false` で記録しないようにできます

## 世代管理（比較・ダウンロード）

「世代管理」画面では、機器ごとに保存したコンフィグの世代（Git のコミット）を一覧し、内容の表示・比較・保存ができます（閲覧者以上）。

- **同じ機器の 2 世代を比べる**: 比べる元（A）と先（B）の世代を選んで「差分を表示」。選択肢にはハッシュと日時を出します。一覧の「A」「B」ボタンからも選べます。一覧には新しい 500 世代まで出ます
- **別の機器と比べる**: 冗長構成の 2 台などを比べます。「別の機器と比べる」で比べる機器を選び「比較する」（既定はどちらも最新。世代を選べば過去の世代どうしも比べられます）。hostname や管理 IP など、機器ごとに違って当然の行も差分に出ます。差分は 2 万行まで表示し、片方 5 万行を超えるコンフィグは比較しません
- **ファイルに保存**: 一覧の「保存」（またはコンフィグ表示中の「ファイルに保存」）で、その世代のコンフィグをテキストファイルでダウンロードします
  - ファイル名は `機器名_世代の日時_ハッシュ8桁.txt`（日時はサーバーのタイムゾーン `TIMEZONE`。同じ世代なら何度保存しても同じ名前）。日本語の機器名もそのまま使い、ファイル名に使えない記号は `_` にします
  - 文字コードは UTF-8、改行は LF（保存時にそろえた内容そのまま）
  - コンフィグには SNMP コミュニティや暗号化されたパスワードなどが含まれることがあるため、**ダウンロードしたことは監査ログに残ります**（機器・世代・サイズ）。画面での表示・比較は記録しません

### 変更へのコメント（作業内容のメモ）

世代ごとに「どんな作業でこの変更が入ったか」をメモできます。後から差分を見返したとき、意図した変更かどうかを確かめるためのものです。

- **書く**: 一覧の「メモ」から（オペレーター以上）。1 世代に 1 件、1000 文字まで、改行も使えます。依頼番号・作業者・作業内容などを書きます
- **読む**: 閲覧者以上。一覧の世代の下、差分・コンフィグの表示の上（比べている A・B それぞれ）、ダッシュボードの「直近の変更」に表示します
- **変更・削除**: 書いた本人と管理者だけ。他の人のコメントは読むだけです。書いた人・最後に変えた人と日時を表示します
- 追加・変更・削除は監査ログに残ります（変更前後の本文の先頭 200 文字を含む）。**パスワードなどの秘密情報は書かないでください**
- 自動収集で変更を検出した直後はコメントがまだ無いため、変更通知やアクティビティにはコメントを出しません
- 機器を削除すると、その機器のコメントも削除します（Git の履歴は従来どおり残ります）

### 変更の確認（確認済み・想定外）

収集で検出した変更（世代）に「確認済み」（意図した変更）か「想定外」（身に覚えのない変更）を付け、まだ付いていない「未確認」の変更を一覧にします。コメントが「何の作業か」を残すのに対し、こちらは「誰かが見て問題ないと判断したか」を残すためのものです。メニュー「コンフィグ」の「変更の確認」（世代管理の下）から開きます。

- **対象**: `config_snapshots`（収集が記録した世代）のうち、各機器の最初の世代（Git の親の無いコミット＝初回の収集）を除いたもの。最初の世代は Git で判定します（snapshot の行の有無には依存せず、プロセス内に覚えるので Git を読むのは機器ごとに初回だけ）。同じ機器・同じ世代が重複していても 1 件として扱います。最初の世代には付けられません（API は 422）。件数（ダッシュボード・状態タブ）も同じ数え方です
- **一覧**: 状態（未確認・想定外・確認済み・すべて。件数付き）・期間（7 日・30 日・90 日・すべて。既定は `CHANGE_REVIEW_DAYS` 日）・機器グループで絞り込みます。新しい順に最大 500 件で、機器名・グループ・世代・収集日時・追加 / 削除の行数・手動 / スケジュール・コメント・確認のメモ・状態を表示します。「差分」から世代管理でその世代の変更（1 つ前との差分）を開きます
- **付ける**: オペレーター以上。行の「確認済み」「想定外」「未確認に戻す」、状態のバッジを押すとメモ（任意・500 文字まで）を書くモーダルが開きます。行を選んで「確認済みにする」でまとめて付けられます（API は 1 回 200 件まで。画面は 200 件ずつに分けて順に送り、途中で失敗したらそこまでの件数と理由を表示します）。閲覧者は状態を読むだけで、操作のボタンは出ません
- **付け直し**: 権限があれば誰でもできます。確認した人・日時は上書きされ、前の状態（状態・メモ・確認した人）は監査ログに残ります
- **世代管理**: 世代の行に状態のバッジ（確認済み＝緑・想定外＝赤・未確認＝灰。最初の世代には出さない）と「確認」ボタン
- 付ける・戻す・まとめて付けるは監査ログ（`config.review` / `config.review_delete` / `config.review_bulk`）に残ります。**メモにパスワードなどの秘密情報は書かないでください**
- 機器を削除すると、その機器の確認の状態も削除します（Git の履歴は従来どおり残ります）
- 未確認の変更を数える期間は `.env` の `CHANGE_REVIEW_DAYS`（既定 30 日、1〜365。変更後は `setup.sh`）。ダッシュボードの「想定外」の件数は期間を問わず数えます

### 基準の世代（ベースライン）とずれの検出

機器ごとに「承認済みの状態」の世代を 1 つ指定し、最新のコンフィグとの差（ずれ）を一覧・ダッシュボード・通知で見られるようにします。「変更の確認」が個々の変更を見たかを残すのに対し、こちらは「いまの状態が承認済みの状態と違うか」を見るためのものです。世代管理と、変更の確認の「基準からのずれ」タブで使います。

- **指定・解除**: オペレーター以上（`config:review`）。世代管理の各行の「基準にする」（確認のモーダルでメモ 200 文字まで）で指定し、上部の「基準を解除」で解除します。1 台に基準は 1 つで、指定し直すと置き換わります。最初の世代も基準にできます。基準にできるのは**その機器に実在する世代だけ**です（存在しない世代・ほかの機器の世代は 404）。閲覧は全員（`config:read`）です
- **ずれの計算**: 基準と最新の本文を比べ、追加・削除の行数を `config_baselines` に保存します（`drift_added` / `drift_removed`、比べた相手の世代 `latest_hash`、計算した日時）。計算するのは (a) 基準を指定したとき (b) 収集で世代が増えたとき（worker が保存の後に実行）(c) 収集に成功したが世代が増えなかったとき、保存した値が最新（HEAD）のものでない・未計算の機器だけ、です（HEAD は本文を読まずに確かめます）。基準の世代そのものが最新なら 0 行です。画面・一覧は保存した値を読むだけで、Git は読みません。Git の読み取りは同期処理なので、API は `run_in_threadpool`、worker は `asyncio.to_thread` で実行します。**再計算に失敗しても収集は成功のまま**で、警告をログに残します。API の指定は、保存の直前に最新が変わっていれば 1 回だけ計算し直します。worker の保存は「読んだときの基準のまま」のときだけ行い、計算の間に基準が付け替えられていたら結果を捨てます（基準と値が食い違わないように）
- **ずれが未計算のとき**: 基準の世代を履歴から読めない・計算に失敗したときは、ずれを「未計算」（`state=unknown`）に戻し、前回の値は出し続けません。一覧には「未計算」と表示し、ずれている機器・基準どおりの数には数えません。基準の世代が履歴に無いなど計算できない状態が続く間、アクティビティに警告（`baseline.error`）を 1 回だけ残します。次の収集の成功時（変更なしの回も）に計算し直し、未計算 → ずれあり になっても通知しません（指定直後と同じ扱い）。基準を指定するとき最新を読めなかった場合も同じく未計算で指定されます
- **世代管理**: 基準の世代の行に「基準」のバッジ、各行に「基準にする」。基準がある機器では上部に「基準 xxxx から +N -M 行のずれ」と「差分を見る」（基準 → 最新の差分）、「基準を解除」を表示します（ずれが無いときは「ずれなし」）。世代の一覧 API（`GET /api/configs/{device_id}/history`）の各行に、その機器の基準の世代 `baseline_hash` を付けます
- **変更の確認 → 基準からのずれ**: ずれている機器の一覧（機器・基準の世代と日時・ずれの行数・最新の世代・メモと指定した人）。「差分」で世代管理に基準 → 最新の差分を開き、「最新を基準にする」でその時点の最新を基準に付け替えます（オペレーター以上。API の `commit_hash` に `latest` を渡し、サーバーが実際の最新の世代を解決します）。未計算の機器も一覧に出ます。基準の無い機器・基準どおりの機器・未計算の機器の数も表示します（`GET /api/configs/baselines?state=drift|ok|unknown|none|all&group_id=`。基準の無い機器も `state=none` で返します）
- **ダッシュボード**: 「基準からずれている機器」のタイル（押すと上のタブを開きます）。基準を指定した機器が 1 台も無いときは出しません
- **通知**: ずれが 0 → 1 行以上になったときだけ送ります（種類 `drift`、通知設定の「基準からのずれ」。**既定は無効**）。基準を指定した直後の計算では通知しません。すでにずれている間・未計算からずれありになったときは、通知しません。ずれが 0 に戻ったときはアクティビティ（`baseline.resolved`）に残すだけです。ずれたときもアクティビティ（`baseline.drift`）に残します。通知は機器名・グループ・ずれの行数・基準と最新の世代・画面へのリンクで、差分の中身は送りません。Discord・Slack・Teams・メールのどれでも送れます
- 指定・解除は監査ログ（`config.baseline_set` / `config.baseline_clear`。付け替えのときは前の基準も残す）に残ります。**メモにパスワードなどの秘密情報は書かないでください**。機器を削除すると、その機器の基準も削除します（Git の履歴は従来どおり残ります）
- 「無視する行」を追加・変更すると、最初の収集で基準との差が増減することがあります（無視した行は保存前に消えるため。基準の世代は変わりません）

## 収集時に無視する行（正規表現）

時刻やカウンタなど、取得のたびに変わる行が原因で毎回「変更あり」になってしまうときに、管理者が画面で行を指定して、保存前に取り除きます。機種ごとにコードで決めてある除外（`PLATFORMS` の `ignore_patterns`）に**加えて**適用します。メニュー「コンフィグ」の「無視する行」（管理者のみ。コンプライアンスの下）から開きます。

- **ルール**: 対象（機種 または 機器）・正規表現（500 文字まで）・説明（任意）・有効 / 無効。機種のルールはその機種のすべての機器に、機器のルールはその 1 台だけに効きます。機器を削除すると、その機器のルールも削除します
- **適用**: 収集のたびに、取得したコンフィグを保存する前に、行ごとに正規表現を `search` し、一致した行を取り除きます（worker が機器を読み込むときに、その機器に効く有効なルール＝機種のもの＋機器のものを読みます）。**過去の世代は変えません**。ルールを追加（削除）した後の最初の収集では、該当の行が消える（戻る）変更が 1 回記録されます（画面にも注意書きがあります）
- **無視した行は、どこからも見えなくなります**: 保存する前に消すので、コンプライアンスの検査・コンフィグ検索・基準との比較からも見えなくなります（画面にも注意書きがあります）。設定の行（`ntp server` など）まで消さないよう、正規表現は狭くしてください
- **試す**: 追加・編集のモーダルの「試す」で、保存せずに、対象の機器の最新の世代に当てます。機種のルールなら同じ機種の機器（50 台まで）、機器のルールならその 1 台について、一致した行数・全体の行数・一致した行の例（機器ごとに 5 行まで、1 行 200 文字まで）を表示します。全行の 50% 以上に一致する機器があれば警告します。保存済みの世代に当てるため、すでに有効なルールで消えた行は出ません（有効なルールを編集して試すと 0 件になります。画面にも注記があります）。一致した行はコンフィグの中身なので、「試す」も管理者（`config:ignore`）だけが使えます。監査ログには正規表現と対象だけを残し、一致した行の中身は残しません
- **検証（422）**: 正規表現として不正なもの、空の行にも一致するもの（`a*` や `^$` など。すべての行が消えてしまう）、空の行への照合すら時間切れになるもの、500 文字を超えるもの、読み込み（コンパイル）が重すぎるもの（「セキュリティ」の「利用者が入力する正規表現の制限」）。検証はイベントループを止めないよう、スレッドで行います
- **広すぎる正規表現の確認（409）**: 保存（追加・更新。有効にするときも）の際に、サーバー側でも「試す」と同じ割合を計算し、対象の機器のどれかで全行の 50% 以上に一致するなら、`confirm_broad: true` が無い限り 409（`detail.code` が `ignore_rule_broad`、`detail.message` に機器名と割合）を返します。画面は「○○ で全行の N% が消えます。保存しますか？」と確認し、了承したら `confirm_broad: true` を付けて送り直します
- **時間の制限（ReDoS 対策）**: 利用者が入れた正規表現を機器の出力に当てるので、`regex` パッケージで時間切れ付きで実行します。1 ルールあたり `IGNORE_RULE_TIMEOUT` 秒（既定 1 秒。全行の合計）、全ルールの合計で `IGNORE_TOTAL_TIMEOUT` 秒（既定 5 秒）。worker も DB から読んだ正規表現の重さを、コンパイルの前に確かめます。「試す」も同じ上限で、時間切れの機器は画面に表示します
- **適用できなかったときは保存しない**: 時間切れ・不正な正規表現・読み込みが重すぎるもので飛ばしたルールが 1 件でもあれば、その回のコンフィグは保存しません（消える回と消えない回が混ざると、偽の変更になるため）。収集は再試行できる失敗として扱い、ほかの失敗と同じく収集ログ・アクティビティ（`collect.failed`）・失敗の通知に乗ります（理由の例:「無視する行の照合が時間切れになりました（ルール: …）」）。あわせて、飛ばした理由ごとにアクティビティに警告（`ignore.timeout` / `ignore.skipped`）を残します。合計の上限を使い切ると、残りのルールも飛ばします。ルールの読み込み（DB）に失敗したときも、接続せずに再試行できる失敗にします
- **収集時の警告**: 追加のルールで全行の 50% 以上が消えたときは、保存は続けたうえで、アクティビティに警告（`ignore.broad`）を残します
- 追加・変更・削除は監査ログ（`ignore_rule.create` / `ignore_rule.update` / `ignore_rule.delete`）に残ります
- 呼び出し側の互換: `normalize_config(text, platform)` と `collect_config_sync(device, triggered_by)` は、引数を足さなくても今までどおり動きます（ルールは `extra_ignore` で渡します）

## 監査ログ

管理者は「監査ログ」画面で、誰が・いつ・何をしたかを確認できます。

- **操作履歴**: ログイン（失敗を含む）、パスワード変更、ユーザーの強制ログアウト、ユーザー・機器（CSV 一括登録を含む）・踏み台・認証情報プロファイル・スケジュール・構成図・コンプライアンスのルールと例外・Ping監視の対象の変更、収集の実行、コンフィグのダウンロード、変更へのコメントの追加・変更・削除、変更の確認（確認済み・想定外・未確認に戻す・まとめて）、基準の世代の指定・解除、ターミナルの接続・切断、ターミナル記録の閲覧・検索、コマンド実行（誰が・どの機器に・どのコマンドを。出力は残さない）と結果の書き出し、監査ログ・アクティビティログ・コンフィグ検索結果の CSV 出力。パスワードや秘密鍵の値は残さず「変更した」ことだけを記録します
- **ターミナルの記録**: SSH ターミナルの画面出力をセッションごとに記録し、画面上で再生できます（asciicast v2 形式。`.cast` としてダウンロードして asciinema でも再生可）
  - キー入力そのものは記録しません（enable のパスワードなど画面に表示されない入力が含まれるため）。入力したコマンドは機器のエコーとして画面出力に残ります
  - 記録は `terminal_logs` ボリューム（`/data/terminal-logs`）に保存。1セッションの上限は 20MB（`TERMINAL_LOG_MAX_BYTES`）
  - 記録は `DEVICE_ENCRYPTION_KEY` で暗号化して保存します（`.cast.enc`。画面出力に show running-config の内容などが残るため）。閲覧・ダウンロード時にサーバーで復号します。`TERMINAL_LOG_ENCRYPT=false` で従来どおり平文（`.cast`）
  - v1.23.0 より前の平文の記録は保持期間で消えるまでそのまま読めます。すぐ暗号化する場合は `sudo podman exec netconfig-manager_backend_1 python -m app.tools.encrypt_recordings`（コンテナ名は `podman ps` で確認）
  - `DEVICE_ENCRYPTION_KEY` を変えると過去の記録は読めなくなります（機器のパスワードと同じ）
- **ターミナルの記録のテキスト**: セッションが終わると、再生用の記録とは別に、**画面に最終的に出た文字だけのテキスト**も保存します（色や制御文字、Backspace での打ち直し、`--More--` の消去の跡を除いたもの）。読み返す・検索する・外部へ渡すためのものです
  - 「ターミナルの記録」の各行の「テキスト」で開き、「ファイルに保存（.txt）」でダウンロードできます（UTF-8・LF。ファイル名は `terminal_ユーザー_機器_開始日時.txt`）
  - 「記録の中を探す」で、打ったコマンドや出力の文字列からセッションを探せます（文字列 / 正規表現。上のユーザー・機器の絞り込みも使います）。新しい順に 300 件まで、全体で 15 秒までを調べ、一致した行からその行を開けます。正規表現はコンフィグ検索と同じく、読み込みが重いものを受け付けません。検索語は URL にも操作履歴にも残しません（検索したこと自体は残します）
  - 扱いは再生用の記録と同じです: 同じ場所に `.txt.enc`（暗号化）で保存、保持期間・バックアップも同じ、閲覧は管理者のみで、見たこと・保存したことは操作履歴に残ります
  - 行は折り返しません（長い設定行を途中で切らないため）。行ごとの時刻は付けません（時刻は「再生」で確認できます）
  - vi や top のように画面全体を書き換える操作は正しく再現されません（その部分は「再生」で確認してください）。キー入力そのものを記録しない点は同じで、画面に出なかった入力はテキストにも入りません
  - この機能を入れる前の記録にはテキストがありません。不要な場合は `.env` に `TERMINAL_LOG_TEXT=false`
- **CSV 出力**: 操作履歴・ターミナルの記録（接続の一覧）を、画面の絞り込み条件のまま CSV で出力できます（「CSV 出力」ボタン。新しい順に最大10万件）
  - Excel でそのまま開けるよう BOM 付き UTF-8。日時はサーバーのタイムゾーン（`TIMEZONE`）で出力します
  - `=` などで始まる値は、表計算ソフトで数式として実行されないよう先頭に `'` を付けます
  - ターミナルの画面の記録そのものは含みません（再生画面から `.cast` でダウンロード）。出力したこと自体も操作履歴に残ります
- **保持期間**: `.env` の `AUDIT_LOG_RETENTION_DAYS`（既定 365 日）・`TERMINAL_LOG_RETENTION_DAYS`（既定 180 日）。毎日1回、期限切れのものを削除します（0 で無期限）

## ユーザーと権限（RBAC）

ユーザーには3つのロールのいずれかを割り当てます。ユーザーの追加・ロール変更・無効化・パスワードリセット・強制ログアウト・2 段階認証の解除は、管理者が「ユーザー管理」画面から行います。

| 権限 | 閲覧者 (viewer) | オペレーター (operator) | 管理者 (admin) |
|---|:-:|:-:|:-:|
| デバイス閲覧 | ✓ | ✓ | ✓ |
| コンフィグ・差分の閲覧・比較（別の機器とも）・ダウンロード | ✓ | ✓ | ✓ |
| スケジュール閲覧 | ✓ | ✓ | ✓ |
| 構成図の閲覧 | ✓ | ✓ | ✓ |
| コンプライアンスの結果・ルールの閲覧 | ✓ | ✓ | ✓ |
| Ping監視の利用 | ✓ | ✓ | ✓ |
| モニタリング（帯域・FW ルールのヒット数）の閲覧 ※試験導入 | ✓ | ✓ | ✓ |
| 脆弱性・サポート期限の閲覧（`VULN_ENABLED=true` のとき。CSV 出力を含む） | ✓ | ✓ | ✓ |
| 変更通知・定期レポートの設定・プレビュー・いま送る（自分の通知設定。メールの宛先を含む） | ✓ | ✓ | ✓ |
| アクティビティ（収集の結果・違反の発生など）の閲覧 | ✓ | ✓ | ✓ |
| 収集の実行（モニタリングの「今すぐ取得」を含む） | | ✓ | ✓ |
| SSHターミナル | | ✓ | ✓ |
| コマンド実行（表示コマンドの一括実行と、結果の閲覧・書き出し。出力に設定の中身が含まれるため閲覧者には付けない） | | ✓ | ✓ |
| 構成図の作成・編集・削除 | | ✓ | ✓ |
| コンプライアンスのルール編集・試す・例外の登録・再検査 | | ✓ | ✓ |
| Ping監視の対象 IP の追加・編集・削除 | | ✓ | ✓ |
| Ping監視の常時監視への追加・解除 | | ✓ | ✓ |
| デバイス登録・編集・削除（CSV 一括登録・モニタリングの SNMP 設定を含む） | | | ✓ |
| 踏み台サーバの登録・編集・削除、認証情報プロファイルの登録 | | | ✓ |
| 認証情報プロファイルの編集・削除・機器への割り当て | | | 所有者と、共有したユーザーグループのメンバー |
| スケジュール編集 | | | ✓ |
| 脆弱性の「確認済み」（メモ必須）とその取り消し・サポート終了日の手入力と削除 | | ✓ | ✓ |
| 脆弱性情報の「いま取得」（外部へ接続する取得の実行） | | | ✓ |
| 変更（世代）へのコメントを書く（他の人のコメントの変更・削除は管理者のみ） | | ✓ | ✓ |
| 変更（世代）に「確認済み」「想定外」を付ける・未確認に戻す（付け直しは誰でも可。状態の閲覧は全員） | | ✓ | ✓ |
| 機器の基準の世代（ベースライン）を指定・解除する（ずれの閲覧は全員） | | ✓ | ✓ |
| 保存されていない変更（startup → running の差分）を見る（`config:read`） | ✓ | ✓ | ✓ |
| 収集時に無視する行（正規表現）の追加・変更・削除・試す（一致した行を表示するため管理者のみ） | | | ✓ |
| ユーザー管理・ユーザーグループ（変更通知のチーム）の管理 | | | ✓ |
| メールサーバー（メール通知の送信設定・テストメール）の設定 | | | ✓ |
| 監査ログの閲覧・CSV 出力 | | | ✓ |
| システム状態（worker・スケジューラーの稼働など）の閲覧 | | | ✓ |
| 自分の 2 段階認証の設定・解除 | ✓ | ✓ | ✓ |
| 自分の API トークンの発行・失効（使える権限は自分のロールの範囲まで。閲覧者は閲覧だけ） | ✓ | ✓ | ✓ |
| ほかのユーザーの API トークンの一覧・全失効 | | | ✓ |
| ほかのユーザーの 2 段階認証の解除 | | | ✓ |
| ダッシュボードの閲覧 | ✓ | ✓ | ✓ |
| コンフィグの横断検索（結果の CSV 出力を含む） | ✓ | ✓ | ✓ |
| 機器台帳（モデル・シリアル番号など）の閲覧・CSV 出力 | ✓ | ✓ | ✓ |

- 割り当ては `backend/app/core/permissions.py` の `ROLE_PERMISSIONS` だけで定義しています。変更する場合はここを編集してください（画面の表示も `/api/auth/me` が返す権限に従って自動で切り替わります）
- 権限チェックはすべてサーバー側で行います。新しいAPIを追加するときは `dependencies=[Depends(require(Perm.XXX))]` を付けてください（付け忘れはテスト `test_every_protected_route_declares_a_permission` で検出されます）
- ロールの変更・無効化は即座に反映されます（ログイン中のユーザーにも次のリクエストから適用）
- パスワードの変更・リセットを行うと、それ以前に発行されたトークンは無効になります
- **2 段階認証（ワンタイムパスワード）**: サイドバーの「2 段階認証」から本人が設定します。設定すると、ログインのときにパスワードのあとで認証アプリ（Google Authenticator・Microsoft Authenticator など）の 6 桁のコードを求めます。パスワードが漏れても、ほかの人はログインできません
  - 設定: 「設定を始める」で表示される QR コードを認証アプリで読み取り（読み取れなければ秘密鍵を手で入力）、表示されたコードで確認すると有効になります。そのとき**予備コード**（10 個）を 1 度だけ表示します。認証アプリを無くしたときに、確認コードの代わりに 1 回ずつ使えます（「予備コードを作り直す」で作り直せます）
  - コードは 30 秒ごとに変わり、前後 30 秒のずれまで受け付けます。同じコードは 2 度使えません。サーバーの時刻がずれているとコードが合わないため、サーバーの時刻を NTP で合わせておいてください
  - 確認コードの誤りもログインの失敗として数え、続けば一時停止します（下の「ログインの試行回数制限」）。ログインに成功すれば、パスワードと確認コードの 2 回分とも数えません（同じ接続元から 2 段階認証のユーザーが何度ログインしても、接続元の制限には達しません）。パスワードを入力してから 5 分以内にコードを入力します
  - 解除: 本人はパスワードとコード（または予備コード）で解除できます。認証アプリも予備コードも無くした場合は、管理者が「ユーザー管理」の「2 段階認証を解除」で解除します（本人であることを確かめてから。監査ログに残ります）
  - 秘密鍵は `DEVICE_ENCRYPTION_KEY` で暗号化して保存し、予備コードはハッシュだけを保存します。認証アプリに表示される名前は `.env` の `MFA_ISSUER`（既定「NetConfig Manager」）
  - いまは任意（設定するかは本人が決める）です。ターミナルの WebSocket・API はログイン後のトークンで動くので、設定前後で使い方は変わりません
- **強制ログアウト**: 「ユーザー管理」の「ログアウトさせる」で、パスワードを変えずにその人の既存のログイン（すべての端末のトークン）と API トークンを無効にできます（本人は同じパスワードで再ログインできます。自分自身には使えません）。アカウントの共有や端末の置き忘れに気づいたときに使います。操作は監査ログに「ユーザーの強制ログアウト」として残ります
  - 無効化でも同じように既存のトークンを無効にし、API トークンも失効させます（有効に戻しても、無効化の前のトークンは使えません）
  - 開いているターミナル: 強制ログアウト・無効化・パスワードのリセット・削除・ターミナルの権限が無いロール（閲覧者）への変更のときは、その人が接続中の SSH ターミナルも切断します（記録の終了理由は「管理者が切断（…）」）。ロールの変更ではログインそのものは切らず、以降の操作が新しいロールで判定されます。本人が「パスワード変更」をしたときも、ほかの PC で開いたままのものを含めて切断します（終了理由は「本人のパスワード変更で切断」）。ただし、この切断は API を 1 プロセスで動かしている場合（既定の構成）だけ確実です。backend を複数のプロセス（`uvicorn --workers` など）で動かすと、ほかのプロセスが受け持つターミナルは切れず、閉じるまで続きます
  - 仕組み: ユーザーごとの番号（`users.token_version`）をトークンに入れて照合し、強制ログアウト・無効化で番号を上げます。この機能より前に発行されたトークンは番号 0 として扱うため、更新直後にログイン中の人が切れることはありません
- 自分自身のロール変更・無効化・削除はできません（有効な管理者が1人もいなくなる操作も拒否されます）
- 操作の記録は「監査ログ」画面で確認できます（管理者のみ）

## API トークン（スクリプト・ほかのシステムから使う）

ログインのトークン（期限 8 時間・2 段階認証あり）は、スクリプトや監視システムなどの外部の仕組みからは使いにくいため、本人が発行する長めの期限の **API トークン** で API を呼べるようにしています。

- **発行**: サイドバー下部の「API トークン」から、名前（用途）・範囲・期限（日数。1〜`API_TOKEN_MAX_DAYS`、既定 90 日）を決め、**いまのパスワードを入れ直して**発行します。値は発行した直後の画面で **1 回だけ**表示します（閉じると二度と表示できません。無くしたら失効させて発行し直します）
  - 発行・失効は、ログインした画面（セッション）からだけ行えます。2 段階認証を設定している人は、2 段階認証を通ったログインから発行することになります。トークンでトークンを発行することはできません
  - パスワードの誤りはログインの失敗と同じく数え、続けば一時的に発行できなくなります（「ログインの試行回数の制限」）
  - 有効なトークンは 1 人 10 個まで。失効・期限切れのものは 30 日間は一覧に残り（いつ最後に使われたかを確かめられるように）、その後は毎日の掃除で消えます
- **範囲**:
  - `read`（閲覧だけ）: GET だけ、かつ閲覧の権限（デバイス・コンフィグ・スケジュール・構成図・コンプライアンス・Ping監視・アクティビティ・モニタリング・監査ログ・システム状態の閲覧。`backend/app/core/permissions.py` の `READ_ONLY_PERMS`）とロールの権限が重なるものだけ。コンフィグ検索のような POST の閲覧も使えません
  - `full`（ロールの権限）: 発行した人のロールの権限で使えます（ただし下の「トークンでは使えない操作」を除く）
  - **`full` は必要なときだけ発行してください**。収集・コマンド実行（表示コマンド）のほか、無視する行・基準の世代・変更の確認・コンプライアンスのルールや例外など、**監視の結果を変える操作**もできます。読むだけなら `read` にします
  - どちらも、リクエストのたびに**いまの**ロールで判定します（ユーザーを無効化・削除すればすぐに使えなくなります）。閲覧者が `full` を選んでも閲覧者の権限のままです
- **使い方**: `Authorization` ヘッダーに `Bearer` で付けます（例のトークンは偽の値です）

  ```bash
  curl -H "Authorization: Bearer ncm_EXAMPLE0000000000000000000000000000000000" \
    https://netconfig.example.test/api/devices/
  # コンフィグの履歴
  curl -H "Authorization: Bearer ncm_EXAMPLE0000000000000000000000000000000000" \
    "https://netconfig.example.test/api/configs/<機器の ID>/history"
  ```

  トークンでの `GET /api/auth/me` は、そのトークンで実際に使える権限（範囲で絞り、トークンで呼べる API が要求するものだけ。`user:admin` などは出ません）と範囲（`api_token_scope`）を返します。API の一覧は `/docs`（Swagger UI）で確認できます（`/docs` と `/openapi.json` はログインなしで見られる現状のままです）
- **トークンでは使えない操作**（権限があっても 403「この操作は API トークンでは行えません。ログインして操作してください」）:
  - API トークンの発行・一覧・失効、パスワード変更、2 段階認証の設定・解除・予備コード、ログイン関係（`/api/auth/*` のうち `/me` 以外）
  - ユーザー管理（ユーザーのトークンの一覧・全失効を含む）、メールサーバーの設定、通知の設定（自分の通知設定・ユーザーグループ。送信先や Webhook の URL を含むため）
  - 認証情報を受け取る・変える操作: 機器の登録・変更・CSV 一括登録、踏み台サーバの登録・変更・削除・接続テスト、認証情報プロファイルの登録・変更・削除・引き継ぎ（と共有先の候補）、モニタリングの SNMP の設定の変更・削除
  - ターミナルの記録の中身（再生・テキスト）と記録の検索、外部 Git への push の実行
  - ターミナル・Ping監視の WebSocket（WebSocket の認証はログインのトークンだけを受け付けます）
  - **新しく作った API は、`backend/app/api/token_policy.py` の一覧（`TOKEN_ALLOWED`）に足さない限りトークンでは呼べません**（既定は不可）。全ルートを「トークンで可・セッションだけ・認証なし」に分けた表を `backend/tests/test_api_tokens.py` に持ち、表に無いルートができるとテストが落ちます
- **失効**: 本人がモーダルの「失効」で、管理者が「ユーザー管理」の「トークンを失効」（その人の全部）で失効させられます。管理者の**強制ログアウト**・**ロールの変更**（昇格で以前の `full` のトークンが強くならないように。降格も同じ）・ユーザーの**無効化**・管理者による**パスワードのリセット**・ユーザーの削除でも、その人のトークンはすべて失効します（監査ログの詳細に失効させた数）
  - **本人の「パスワード変更」では失効しません**（パスワードの定期変更でスクリプトが止まらないように）。**トークンが漏れた疑いがあるときは、パスワード変更ではなく、本人か管理者がトークンを失効させてください**
- **発行の応答**: 値を含む応答には `Cache-Control: no-store`・`Pragma: no-cache` を付け、ブラウザや中継にキャッシュさせません。名前に制御文字・見えない書式文字（右から左への切り替え・ゼロ幅の文字など）は使えません。日数は整数だけです。画面の日数の上限は `API_TOKEN_MAX_DAYS` に合わせます
- **保存の仕方**: トークンは `ncm_` ＋ 乱数（`secrets.token_urlsafe(32)`、256 ビット）です。DB には SHA-256 のハッシュと、見分けるための先頭 12 文字（`ncm_` ＋ 8 文字）だけを保存し、値そのものは保存しません。ログ・監査ログ・エラーの文言にも値は出しません
- **記録**: 最後に使った日時と接続元を 1 分に 1 回まで記録し、一覧に表示します。トークンで行った操作は、監査ログの「誰が」はユーザー名のまま、詳細に `via_token`（トークンの名前）を付けます。発行・失効・全失効は監査ログ（「API トークンの発行」「API トークンの失効」「API トークンの全失効（管理者）」）に残ります
- **総当たりへの対策**: 照合に失敗したトークン（形式の誤り・存在しない値。**掃除で行が消えた古いトークンも含む**）を、ログインとは別のカウンタで接続元ごとに数えます。`LOGIN_FAILURE_WINDOW_MIN` 分（既定 10 分）の間に `LOGIN_MAX_FAILURES_PER_IP` 回（既定 20 回）を超えた接続元は、`LOGIN_LOCK_MIN` 分（既定 15 分）、照合に失敗したトークンに 429 を返します（監査ログに「ログインの一時停止」、詳細は「接続元（API トークン）」）
  - ログインのロックとは互いに影響しません。壊れたスクリプトが古いトークンを送り続けても、同じ接続元の人のログインや、正しいトークンは止まりません（正しいトークンはロック中でも通します）
  - 正しいトークンと、失効・期限切れでまだ一覧に残っているトークンは数えません。Redis に接続できないときは、ログインと同じく制限せずに続けます
- **無効にする**: `.env` で `API_TOKENS_ENABLED=false` にすると、発行も、発行済みのトークンでの利用もできなくなります（トークンは消えないので、`true` に戻せば有効期限内のものはまた使えます）

## セキュリティ

- **認証**: `/api/auth/token` と `/api/health` 以外の API はすべてログイン（または API トークン。「API トークン」参照）が必要です。WebSocket ターミナルは接続直後のメッセージでトークンを検証し（SSH の接続後にもう一度確認）、ターミナル権限が無ければ切断します。接続中の再検証は行わず、管理者の強制ログアウト・無効化・パスワードのリセット・削除・ターミナルの権限が無いロールへの変更、本人のパスワード変更のときにサーバーから切断します（上記「強制ログアウト」の制約を参照）
- **機器パスワード**: DB には Fernet で暗号化して保存します。旧バージョンで平文保存されていたものは backend 起動時に自動で暗号化されます
- **SSHホスト鍵**: known_hosts を `ssh_data` ボリューム（`/data/ssh/known_hosts`）で backend と worker が共有します
  - `tofu`: 初回接続時に鍵を記録し、以後は一致しなければ接続を拒否（機器を入れ替えた場合は known_hosts から該当行を削除）
  - `strict`: known_hosts に事前登録したホストにのみ接続
- **収集したコンフィグ**: パスワードハッシュや SNMP コミュニティ等が含まれるため、`config_repo` ボリュームのアクセス権・バックアップ先の扱いに注意してください
- **ターミナルの記録**: 機器の画面出力（show running-config の結果など）がそのまま残るため、`terminal_logs` ボリュームも同様に扱ってください。閲覧は管理者のみで、閲覧したこと自体も操作履歴に残ります
- **コマンド実行**: 設定を変えるコマンドを送らせないことが要です。許可リスト（機種ごとの先頭の語・絞り込み）・危険な文字の拒否・件数と長さの上限を、API と worker の両方で検証します（詳しくは「コマンド実行」）。出力には設定の中身が含まれるため、暗号化して保存し、`command:run`（`config:read` を持つロールだけ）がある人にだけ見せ、`COMMAND_RUN_RETENTION_DAYS` で削除します。監査ログには出力を入れません
- **ログインの試行回数の制限**: 失敗を Redis で数え、同じユーザー名・同じ接続元から `LOGIN_MAX_FAILURES` 回（既定 5 回）、または同じ接続元から（ユーザー名を問わず）`LOGIN_MAX_FAILURES_PER_IP` 回（既定 20 回）失敗すると、`LOGIN_LOCK_MIN` 分（既定 15 分）その接続元からのログインを止めます（失敗を数える期間は `LOGIN_FAILURE_WINDOW_MIN`、既定 10 分）
  - ユーザー名だけでは止めないため、ほかの端末から管理者を締め出すことはできません。存在しないユーザー名でも同じように止まるので、応答からユーザーの有無は分かりません
  - 止めたときは監査ログに「ログインの一時停止」を記録します。期限を待たずに解除するには `podman exec <redis のコンテナ> redis-cli --scan --pattern 'netconfig:login:lock:*'` で該当のキーを確認し、`redis-cli del <キー>` で削除します
  - 試行はパスワードを照合する前に数えるため、同時に大量のリクエストを送っても上限を超えて照合されることはありません。成功したログインは回数に含めません
  - Redis に接続できないときは制限せずにログインを通します（Redis が止まっても管理者が入れるように）
- **接続元 IP**: 監査ログ・ログインの制限で使う接続元 IP は、nginx が付ける `X-Forwarded-For`（利用者が送った値は nginx で上書き）から取ります。backend のポートを外部に公開しないでください（公開すると接続元を偽装できます）
- **コンプライアンスの正規表現**: 利用者が入力した正規表現は `regex` パッケージで照合し、1回の評価（ルール × 機器）あたり `COMPLIANCE_REGEX_TIMEOUT` 秒（既定 2 秒）で打ち切ります（照合に時間のかかるパターン＝ReDoS で API・worker が止まらないように）。打ち切った評価は「エラー」になります。保存前の「試す」はオペレーター以上
- **利用者が入力する正規表現の制限**: 無視する行・コンプライアンス（ルール・セクションの見出し・例外）・コンフィグ検索・ターミナル記録の検索の正規表現は、「読み込み（コンパイル）の重さの確認 → コンパイル → 時間切れ付きの照合」の順で扱います（`backend/app/core/safe_regex.py`）
  - 照合の時間切れは打ち切れますが、コンパイルは打ち切れません。`(((a{100}){100}){100}){10}` のような回数指定の繰り返しの入れ子や、`((((a)+)+)+)+…` のような `+` の入れ子（1 段ごとに大きさが倍になる）は、コンパイルだけで数秒・数 GB を使います
  - そこで、回数指定の繰り返し（`{`）を含むものと `+` が 7 個以上あるものは、**別のプロセス（新しく起動した Python）で実際に読み込んで測り**、重いものは登録できません（422。「この正規表現は読み込みが重すぎます」）。重いとするのは、読み込みでメモリ（最大 RSS。`/proc/self/status` の `VmHWM`）が 16MB を超えて増えるもの、CPU 時間が 0.5 秒を超えるもの、子のプロセスの上限（regex を読み込んだあとのメモリ＋64MB、CPU 2 秒）で止まったものです。普通のルール（IP アドレスをいくつも含むもの・`.{0,200}` など）は数 ms・1MB 未満で通ります
  - それ以外（`{` が無く `+` が 6 個以下）は、大きさがパターンの長さにほぼ比例するので、そのまま読み込みます
  - 確定した判定（通す・重い・不正）は覚えておき（2048 件）、同じパターンで何度も測りません。測るプロセスは同時に 2 つまで（空きは 3 秒まで待つ）です
  - 測るプロセスを起動できない・3 秒で終わらない・異常終了したときは、判定を覚えずに「確かめられませんでした」として受け付けません（API は 503。ログに理由を残します）。収集の「無視する行」ではその回のコンフィグを保存せず再試行できる失敗に（アクティビティは `ignore.unavailable`）、コンプライアンスの検査ではそのルールをその回だけ「エラー」にし、次の検査でまた確かめます
  - 読み込んだものは件数（16 件）と測ったメモリの合計（64MB）の上限の中で使い回し、`regex` の内部キャッシュには残しません（違うパターンを続けて読み込んでもメモリが増え続けないように）
  - 括弧の入れ子が深すぎるもの（数百段）は「不正な正規表現」として扱います（422）
  - 文字数は入力欄ごとの上限（無視する行 500、コンプライアンスのルール 1000、見出し・例外 500、検索 200）
  - `(a+)+$` のような照合だけが重いパターンと、`regex` パッケージのあいまい一致（`{e<=3}` など）の照合の重さは、照合の時間切れで守ります
  - 確認（コンパイル）はイベントループを止めないよう、スレッドで行います。worker も DB から読んだ正規表現の重さを、コンパイルの前に確かめます（重いルールは「エラー」、無視する行はその回のコンフィグを保存しない）
- **セキュリティヘッダー**: 本番の nginx（`frontend/nginx/`）が、画面・API のすべての応答に次のヘッダーを付けます（開発用の vite のサーバーでは付きません）
  - `Content-Security-Policy`（CSP。値は `frontend/nginx/csp.inc`）: スクリプト・接続先・画像・フォントを同じサーバーのものに限ります（ログインのトークンをブラウザに保存しているため、万一画面に不正なスクリプトが入り込んでも、外部のスクリプトの読み込みや外部への送信をブラウザが止めるように）。インラインのスクリプトと `eval` は許可しません。例外は、スタイルのインライン（`style-src 'unsafe-inline'`。ターミナルの表示と構成図の印刷で必要）と `data:` の画像（`img-src data:`。構成図の PNG / PDF 書き出し・印刷で必要）だけです。画面のフォント（Inter・Noto Sans JP・JetBrains Mono）はビルドに含めて同じサーバーから配信し、外部（Google Fonts など）からは読み込みません（閉じたネットワークでも表示が変わりません）
  - `/docs`（API ドキュメント。Swagger UI）だけは、外部（cdn.jsdelivr.net）のスクリプトとインラインのスクリプトを使うため、それらを許可した別の CSP にしています（閉じたネットワークでは従来どおり表示されません）
  - `Strict-Transport-Security`（HSTS）: HTTPS で配信しているときだけ `max-age=86400`（1 日）を付けます。自己管理の CA の証明書で運用しているため、証明書の期限切れなどで HTTPS が使えなくなったときに入れなくなる期間を短くしています。社内のほかのサブドメインを巻き込まないよう `includeSubDomains` は付けず、ブラウザへの事前登録（`preload`）もしません。HTTPS で運用していて外したい場合は `frontend/nginx/https.conf` の行を消して frontend を再ビルドしてください
  - `X-Content-Type-Options: nosniff`・`X-Frame-Options: DENY`（CSP の `frame-ancestors 'none'` と同じく、ほかのサイトの枠内に表示させない）・`Referrer-Policy: same-origin`・`Permissions-Policy`（カメラ・マイク・位置情報などを使わない）
  - nginx の `location` の中に `add_header` を書くと、その場所では上のヘッダーが付かなくなります。設定を変えるときは `csp.inc` の `map` で値を切り替えてください
- **依存パッケージの脆弱性**: GitHub Actions（`.github/workflows/audit.yml`）で push のたびと毎週月曜に `pip-audit`（backend）と `npm audit --omit=dev`（frontend）を実行します。backend の依存はロックファイルで全部の版を固定しており、`pip-audit` は本番に入る版そのものを検査します（更新の手順は「テスト」の「依存パッケージの更新」）
  - 例外: paramiko の `PYSEC-2026-2858`（ssh-rsa＝SHA-1 署名を許可している）は除外しています。修正版の paramiko 5 は ssh-rsa を廃止しており、ssh-rsa しか使えない古いネットワーク機器へ接続できなくなるためです。古い機器が無くなったら paramiko 5 へ更新して除外を外してください

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
pip install --require-hashes -r requirements-dev.txt   # 本番の依存も同じ版で含む（Python 3.12 推奨）
pytest
```

コンテナ内で実行する場合:

```bash
docker compose run --rm backend sh -c "pip install --require-hashes -r requirements-dev.txt && pytest"
```

リンター（ruff。設定は `backend/ruff.toml`）:

```bash
cd backend
ruff check .          # 指摘の確認
ruff check --fix .    # 自動で直せるものを修正
```

画面テスト（Playwright。`frontend/e2e/`）: backend を SQLite で起動し、初期データ（`e2e/seed.py`）を入れてから Chromium で操作します（全画面を開けるか・左ペインの大項目の開閉・ログイン・権限・グループ・世代管理（2 世代・別の機器との比較、コンフィグの保存、変更へのコメント）・変更の確認（一覧 → 確認済み → 世代管理のバッジ・ダッシュボード）・基準の世代（基準にする → バッジ・ずれのタブ・ダッシュボード → 最新を基準にする → 解除）・コンプライアンスの例外・構成図の編集と書き出し・監査ログの CSV・認証情報プロファイルの割り当てなど）。
`csp` プロジェクト（`e2e/tests/csp.spec.ts`）だけは、本番ビルド（`dist/e2e-csp`）を本番の nginx と同じ CSP（`nginx/csp.inc` から読み取る）を付けて配信し（`e2e/vite.csp.config.ts`。4173 番）、全画面・構成図の書き出しと印刷・CSV のダウンロード・WebSocket が CSP に止められないこと、外部から何も読み込まないことを確かめます（開発サーバーはホットリロード用のインラインのスクリプトを使うため、本番と同じ CSP では確認できません）。

```bash
cd frontend
npx playwright install chromium   # 初回のみ
PYTHON=python3 npm run e2e         # backend の依存パッケージが入った Python を指定
```

GitHub に push すると、GitHub Actions（`.github/workflows/ci.yml`）が自動で次を実行します（結果はリポジトリの「Actions」タブで確認）:

- backend: ロックファイルが `requirements*.in` と合っているかの確認（`scripts/lock_deps.sh --check`）、ruff、導入・運用スクリプトの構文検査（`bash -n scripts/*.sh scripts/lib/*.sh`）、pytest（Python 3.12。`tests/test_os_scripts.py` が、偽の os-release と偽のコマンドで AlmaLinux・Ubuntu の分岐を確かめます。`tests/test_setup_script.py` は `setup.sh` を最初から最後まで走らせます。一時ディレクトリの中に導入先を作り、PATH の先頭に置いた偽のコマンド（sudo・dnf・apt-get・git・podman・podman-compose・firewall-cmd・ufw・systemctl・curl など。呼び出しを記録するだけ）で、AlmaLinux 10・Ubuntu 24.04 のそれぞれについて、初回（パッケージの導入・`.env` の作成とキー・ポート開放・ビルドと起動・自動起動・最後の確認）、更新（`.env` が 1 バイトも変わらない・`git pull`・再ビルドとコンテナの再作成・`setup.sh` が変わったときのやり直し）、途中の失敗（ビルド・起動の失敗で 0 以外で終わり、後の手順を呼ばない）、対象外の OS で止まること（dnf があっても）、`.env` の書き方（末尾の改行なし・CRLF・引用符つきのポート・`=` `#` `$` を含む値）でも更新で 1 バイトも変わらないこと、末尾に改行が無い古い `.env` に足りないキーが別の行として足されること、バックアップを `.env` の変更より前に取ること、`endfield-news-bot`・crontab・`python3-pip` に触れないこと、`rm -rf`・`podman system prune`・`volume rm`・`down -v`・パッケージの削除のような消す操作を呼ばないことを、記録から確かめます。偽の sudo は、`/opt`・`/etc`・`/root`・`/var`・`/usr`・`/run`・`/sys` など一時ディレクトリの外のパスが引数のどこかに含まれる呼び出しを実行せずに落とすので、実際のサーバーの設定には触れません。実機の動作の確認ではありません）
- frontend: `npm ci` → 型チェック（tsc）→ 本番ビルド（vite build）（Node.js 22）
- nginx: `frontend/Dockerfile` と同じ nginx のイメージか、脆弱性の修正版（`NGINX_MIN`、今は 1.30.7）以上かを確かめ、設定を読み込み（`nginx -t`）、HTTPS・HTTP のそれぞれで起動して、CSP・HSTS などのヘッダーが付くこと（HSTS は HTTPS のときだけ）を確かめます
- e2e: 画面テスト（`csp` プロジェクトを含む。失敗したときはレポートとスクリーンショットを Artifacts に保存）

あわせて `.github/workflows/audit.yml` が、依存パッケージの既知の脆弱性を確認します（push のたびと毎週月曜。backend は `pip-audit` でロックファイルに書かれた版をそのまま検査、frontend は `npm audit --omit=dev --audit-level=high`）。同じワークフローの `image-scan` は、本番のイメージを Trivy（版とハッシュを固定）で検査します（OS のパッケージ・nginx など、ロックファイルの外にあるもの）。ここでビルドする backend・frontend は、修正版が出ている HIGH 以上の脆弱性があれば失敗します（土台の系列が古ければ Dockerfile のタグを上げます）。公式のイメージをそのまま使う PostgreSQL・Redis は、こちらでは直せないので結果を表示するだけです（公式が作り直したら `setup.sh` で取り直します）。`deps-smoke` は、本番と同じく `requirements.txt`（ロックファイル）だけを入れた環境で API・worker を読み込み、Redis へタスクを登録できるかを確かめます（テストのジョブは開発用パッケージも入れるため、本番にだけ無いパッケージへの依存を見逃すことがあるため。ロックファイルは「宣言されていない依存」の不具合もそのまま固定してしまうので、ロックを更新したときの確認として残しています）。

### 依存パッケージの更新（ロックファイル）

backend の依存は、人が編集する `backend/requirements.in`（直接使うパッケージ。`==` で固定）と、そこから生成するロックファイル `backend/requirements.txt`（間接的な依存も含めて全部の版とハッシュを固定）に分けています。本番のイメージは `pip install --require-hashes -r requirements.txt` で入れるので、再ビルドしても版が変わらず、ロックに無いパッケージや中身の違うファイルは入りません。開発・テスト用は `requirements-dev.in` → `requirements-dev.txt`（本番の依存も同じ版で含む）です。**ロックファイルは手で編集しないでください**（CI が検出して失敗します）。

生成には [uv](https://docs.astral.sh/uv/) を使います（`pip install uv==0.11.32`。CI と同じ版）。本番のコンテナ（`python:3.12-slim`）と同じ Python 3.12 向けに、OS を問わない形で解決するので、手元の Python の版や OS は問いません。

```bash
# パッケージを追加・版を変える: backend/requirements.in（開発用は requirements-dev.in）を編集してから
bash scripts/lock_deps.sh                  # 変えたところだけロックに反映（ほかの版はそのまま）

# 間接的な依存だけを上げる（pip-audit で脆弱性が見つかったときなど）
bash scripts/lock_deps.sh -P パッケージ名

# .in で固定していない間接的な依存をすべて新しい版にする（影響が大きいので、上げたら下の確認を必ず行う）
bash scripts/lock_deps.sh --upgrade

# ロックが .in と合っているかの確認（CI と同じ）
bash scripts/lock_deps.sh --check
```

- 更新したら、`pip install --require-hashes -r backend/requirements-dev.txt` で入れて pytest を実行し、差分（`git diff backend/requirements*.txt`）を確認して `.in` と一緒にコミットしてください。push 後は CI の `deps-smoke` で本番の依存だけでの起動も確かめられます
- 意図して固定しているもの（`requirements.in` のコメント参照。消さないこと）: kombu 5.6.2（5.7.0 は依存の宣言漏れで本番の worker が Redis に接続できない）、paramiko 3.5.1（5 系は ssh-rsa を廃止し古い機器へ接続できなくなる）
- 本番の Python を 3.13 などに上げるときは、`scripts/lock_deps.sh` の `--python-version` を変えてロックを生成し直してください

### 依存の更新の通知（Dependabot）

**実際に PR が来るのは、主に GitHub Actions と npm です**（イメージは、下に書くとおり、タグの形と除外のためほとんど来ません）。

`.github/dependabot.yml` で、GitHub の Dependabot が週 1 回（月曜 9 時。日本時間）、更新を **プルリクエスト（PR）で知らせます**（自動では取り込みません）。対象は、土台のイメージ（`backend/Dockerfile` の python、`frontend/Dockerfile` の node・nginx、`docker-compose.yml`・`docker-compose.prod.yml` の postgres・redis）、GitHub Actions（`.github/workflows/` の `uses:`）、npm（`frontend/`）です。ecosystem ごとに PR は 3 件までで、マイナー・パッチはまとめて 1 本の PR になります。

- **提案させないもの**: nginx のマイナー・メジャー（`1.30-alpine` のように 2 段のタグは段数が保たれるため、パッチの PR は出ず、nginx の PR も実質来ません。安定版の切り替え 1.30 → 1.32 は年 1 回ほど手で行います）、node・postgres・redis のメジャー版（PostgreSQL は上げるとデータの移行が要ります）、python のメジャー・マイナー版（3.12 → 3.13。依存のロックと CI を 3.12 に固定しているため）
- **postgres・redis・node・python は、実際には PR がほとんど来ません**: タグが `16-alpine` のようにメジャー（python は `3.12`）までの形で、メジャー（python はマイナーも）を除外しているためです。同じタグの中身の更新は `setup.sh` の取り直しで入り、古さは画面「システム状態」の「コンテナのイメージ」で分かります
- **npm のメジャー版は提案させないもの**: `typescript`・`react`・`react-dom`・`@types/react`・`@types/react-dom` のメジャー版（`version-update:semver-major`）は `ignore` に入れています（画面の改修とセットで手で上げます。マイナー・パッチは `groups` の PR に入ります）
- **PR が来たとき**: CI（`ci.yml`・`audit.yml`）が通ったことを確認して取り込みます。取り込んだあと、サーバーで `bash scripts/setup.sh` を実行すると、イメージの取り直しと再ビルドで反映されます。イメージの PR は、Trivy の検査（`image-scan`）が通ることも確認してください
- **nginx の PR（通常は来ません。来た場合）**: `ci.yml` の `IMAGE`（と、`NGINX_MIN` を上げる場合はその値）が `frontend/Dockerfile` と食い違うため、**同じブランチで `ci.yml` を直すまで CI の nginx のジョブが落ちます**。
- **nginx の安定版の切り替え**（1.30 → 1.32 など。年 1 回ほど、手で行います）: 奇数のマイナー版（mainline）は使いません。`frontend/Dockerfile` の `FROM docker.io/library/nginx:1.30-alpine AS prod` と、`.github/workflows/ci.yml` の `IMAGE`・`NGINX_MIN` を **同じコミットで**直し、README の「1.30」の記載（上の「テスト」の nginx の説明など）も合わせます。CI の nginx のジョブ（`nginx -t`・ヘッダーの確認）が通ってから取り込み、サーバーで `setup.sh` を実行します。
- **pip は Dependabot の対象にしていません**: ロックファイル（`requirements*.txt`）は uv で生成し、CI が `scripts/lock_deps.sh --check` で `.in` との一致を確かめているため、Dependabot の PR はほぼ確実に CI で落ちます。意図して固定している kombu・paramiko を上げる PR も出てしまいます。pip の更新は、`audit.yml` の `pip-audit`（毎週）で脆弱性を知り、「依存パッケージの更新（ロックファイル）」の手順（`scripts/lock_deps.sh`）で上げます
- **Dependabot の対象外で、手で上げるもの**: `ci.yml` の `IMAGE` と `NGINX_MIN`、`audit.yml` の `services` の `redis:7-alpine`、`ci.yml`・`audit.yml` の `python-version`・`node-version`、uv の版（`pip install uv==…`。`ci.yml`・README・`scripts/lock_deps.sh` の `UV_VERSION`）、Trivy の版とハッシュ（`audit.yml` の `TRIVY_VERSION`・`TRIVY_SHA256`）、pip のロック（上記）
- 設定を変えるときは、`dependabot.yml` の `ignore`・`groups` を編集します。GitHub 側で Dependabot version updates が有効になっていないと PR は来ません（リポジトリの Settings → Code security の「Dependabot version updates」）

---

## RHEL 10 本番設定

（Ubuntu 24.04 LTS の違いは、上の「Ubuntu 24.04 LTS で使う」を参照）

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
# 本番構成（nginx）は HTTP / HTTPS ポートのみ開放（setup.sh・import_cert.sh が自動で行う）
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## ディレクトリ構成

```
netconfig-manager/
├── .github/workflows/ci.yml     # GitHub Actions（テスト・ビルドの自動実行）
├── .github/workflows/audit.yml  # GitHub Actions（依存パッケージの脆弱性の確認。毎週も実行）
├── .github/dependabot.yml       # Dependabot（イメージ・Actions・npm の更新を PR で通知。毎週。pip は対象外）
├── docker-compose.yml           # 開発用
├── docker-compose.prod.yml      # 本番用（nginx 配信）
├── .env.example
├── certs/                       # HTTPS の証明書（import_cert.sh で配置。Git 管理外）
├── certs-outbound/              # 外部への接続で追加で信頼する CA（OUTBOUND_CA_FILE。Git 管理外。README.md だけ管理）
├── scripts/
│   ├── lib/os.sh                # OS の判定と、OS ごとに違う操作（パッケージ・ファイアウォールなど。AlmaLinux / Ubuntu）
│   ├── lib/proxy.sh             # 外部への通信のプロキシ・追加の CA（setup.sh・check_env.sh が読む。伏せ字・sudo への受け渡し）
│   ├── setup.sh                 # 自動セットアップ・更新
│   ├── check_env.sh             # 導入前チェック
│   ├── import_cert.sh           # HTTPS 化（証明書の取り込み）
│   ├── lock_deps.sh             # backend の依存のロックファイルの生成・確認（uv）
│   ├── backup.sh                # バックアップ（setup.sh が毎日実行するよう登録）・サーバー外へのコピー・結果の報告
│   ├── restore.sh               # バックアップからの復元
│   └── collect_logs.sh          # 調査用のログをまとめる（起動しない・動きがおかしいとき）
├── backend/
│   ├── Dockerfile
│   ├── build-ca/                # ビルド用の追加の CA の写し（setup.sh が certs-outbound/ から置く。Git 管理外。README.md だけ管理）
│   ├── requirements.in          # 依存パッケージ（直接使うもの。人が編集する）
│   ├── requirements.txt         # ロックファイル（全部の版とハッシュ。lock_deps.sh で生成し、手で編集しない）
│   ├── requirements-dev.in      # テスト用の依存パッケージ
│   ├── requirements-dev.txt     # テスト用のロックファイル（本番の依存も同じ版で含む）
│   ├── alembic.ini              # DBマイグレーション設定
│   ├── migrations/versions/     # マイグレーション
│   ├── tests/                   # pytest
│   ├── ruff.toml                # リンター（ruff）の設定
│   └── app/
│       ├── main.py              # FastAPI エントリーポイント・起動時の移行処理
│       ├── worker.py            # Celery タスク定義（収集・スケジュール実行・定期コンプライアンスチェック・モニタリングの定期取得・コマンド実行の機器 1 台ぶん）
│       ├── tools/
│       │   ├── backup_report.py # バックアップの結果をアプリに記録（backup.sh・setup.sh が podman exec で実行）
│       │   ├── image_report.py  # コンテナのイメージの作成日時をアプリに記録（setup.sh が podman exec で実行）
│       │   ├── encrypt_recordings.py  # 既存の平文のターミナル記録を暗号化（podman exec で実行）
│       │   └── selfcheck.py     # 更新後の自己診断（worker・スケジューラーが動くか。setup.sh が実行）
│       ├── core/
│       │   ├── config.py        # 設定
│       │   ├── database.py      # DB セッション
│       │   ├── security.py      # パスワードハッシュ・JWT（2 段階認証の途中の印を含む）
│       │   ├── totp.py          # 2 段階認証のワンタイムパスワード（RFC 6238）・予備コード・QR コード
│       │   ├── permissions.py   # ロールと権限の定義（RBAC）
│       │   ├── crypto.py        # 機器パスワード暗号化
│       │   ├── csv_export.py    # CSV 出力の共通処理（監査ログ・アクティビティ）・ダウンロードのファイル名
│       │   ├── outbound.py      # 外部への HTTPS の共通部品（プロキシ・NO_PROXY・追加の CA・失敗の文・伏せ字・接続の確認）
│       │   ├── safe_regex.py    # 利用者が入力する正規表現の読み込みの重さの確認（別のプロセスで測る）とコンパイル（無視する行・コンプライアンス・検索で共通）
│       │   ├── ssh_hostkeys.py  # SSH ホスト鍵検証
│       │   ├── ssh_keys.py      # SSH 秘密鍵の読み込み（機器・踏み台共通）
│       │   ├── ssh_jump.py      # 踏み台経由の接続
│       │   └── migrate.py       # 起動時のDBマイグレーション
│       ├── models/
│       │   ├── __init__.py      # モデル登録
│       │   ├── base.py
│       │   ├── device.py        # Device / DeviceGroup / JumpHost / CredentialProfile / ConfigSnapshot / ConfigComment / CollectLog / Schedule
│       │   ├── topology.py      # TopologyMap（構成図）
│       │   ├── compliance.py    # ComplianceRule / ComplianceResult / ComplianceException
│       │   ├── ignore_rule.py   # ConfigIgnoreRule（収集時に無視する行の正規表現。機種・機器ごと）
│       │   ├── command_run.py   # CommandRun / CommandResult（コマンド実行の実行と、機器ごとの結果。出力は暗号化）
│       │   ├── api_token.py     # ApiToken（API トークン。値はハッシュだけ保存）
│       │   ├── activity.py      # ActivityLog（システムで起きたこと）
│       │   ├── audit.py         # AuditLog（操作履歴）/ TerminalSession（ターミナルの記録）
│       │   ├── mail.py          # MailServer（メール通知の送信設定。SMTP・OAuth 2.0）
│       │   ├── notification.py  # UserGroup / UserGroupMember / NotificationSetting（通知）
│       │   ├── ping.py          # PingTarget（Ping監視で追加した IP）・PingMonitor / PingResult（常時監視の対象と結果）
│       │   ├── monitoring.py    # SnmpSetting / MonInterface / IfSample / FwRuleHit / FwHitStatus（モニタリング）
│       │   ├── vuln.py          # VulnAdvisory / VulnMatch / EolDate / VulnSource（脆弱性・サポート終了日）
│       │   └── user.py          # User
│       ├── api/
│       │   ├── deps.py          # 認証・権限チェック（require。API トークンの検証・範囲の判定・require_session）
│       │   ├── token_policy.py  # API トークンで呼べる API の一覧（既定は不可）
│       │   ├── auth.py          # ログイン・パスワード変更
│       │   ├── api_tokens.py    # API トークンの発行・一覧・失効（本人。ログインのセッションからだけ）
│       │   ├── devices.py       # デバイス CRUD + 収集トリガー + CSV 一括登録
│       │   ├── device_groups.py # 機器のグループ CRUD・所属の一括変更
│       │   ├── jump_hosts.py    # 踏み台サーバ CRUD + 接続テスト
│       │   ├── credential_profiles.py # 認証情報プロファイル CRUD（複数の機器で共有するアカウント）
│       │   ├── configs.py       # 履歴・差分・別の機器との比較・ダウンロード・横断検索 API
│       │   ├── config_comments.py # 世代へのコメント（作業内容のメモ）の API
│       │   ├── config_reviews.py # 変更の確認（確認済み・想定外）の API・未確認の変更の一覧
│       │   ├── config_baselines.py # 基準の世代（ベースライン）の指定・解除・ずれの一覧
│       │   ├── tasks.py         # 収集タスクの状態確認
│       │   ├── users.py         # ユーザー管理（管理者のみ。強制ログアウト・API トークンの一覧と全失効を含む）
│       │   ├── terminal.py      # WebSocket SSH ターミナル（接続中の一覧を持ち、強制ログアウト・ロール変更・パスワード変更で切断）
│       │   ├── topology.py      # 構成図 CRUD・機器の収集状態
│       │   ├── compliance.py    # コンプライアンスのルール・結果・例外・テンプレート
│       │   ├── ignore_rules.py  # 収集時に無視する行のルール CRUD・保存前に試す（管理者のみ）
│       │   ├── commands.py      # コマンド実行（表示コマンドの一括実行）の作成・進み具合・結果・書き出し・入力中の検証
│       │   ├── activity.py      # アクティビティログの閲覧
│       │   ├── audit.py         # 監査ログの閲覧・CSV 出力（管理者のみ）
│       │   ├── mail.py          # メールサーバーの設定・テストメール・Google アカウントの同意
│       │   ├── notifications.py # 通知設定（自分）・ユーザーグループ・通知先の確認
│       │   ├── ping.py          # Ping監視の対象 CRUD・WebSocket で結果を配信・常時監視の登録 / 状態 / 推移
│       │   ├── system.py        # システムの状態（worker・スケジューラーの稼働など）
│       │   ├── dashboard.py     # ダッシュボードの要約（収集状況・直近の変更・違反・次のスケジュール）
│       │   ├── monitoring.py    # モニタリング（SNMP 設定・帯域・FW ヒット数。MONITORING_ENABLED のときだけ有効）
│       │   ├── vulns.py         # 脆弱性・サポート期限（要約・一覧・機器別・確認済み・サポート終了日の手入力・いま取得。VULN_ENABLED のときだけ有効）
│       │   └── schedules.py     # スケジュール CRUD
│       └── services/
│           ├── config_service.py # 対応プラットフォーム（PLATFORMS）・Netmiko での収集・GitPython
│           ├── compliance.py    # コンプライアンスの評価エンジン（例外の適用を含む）
│           ├── ignore_rules.py  # 無視する行の適用（時間切れ付き）・ルールの読み込み・試す
│           ├── command_run.py   # コマンド実行: 送れるコマンドの検証（機種ごとの許可リスト）・出力の上限・同じ出力のまとめ・保持期間の掃除
│           ├── baseline.py      # 基準の世代と最新のコンフィグのずれ（追加・削除の行数）の計算
│           ├── collect_state.py # 収集の進み具合（待ち・収集中・再試行待ち）を Redis に置く
│           ├── config_search.py # コンフィグの横断検索（最新コンフィグを1行ずつ照合、時間制限つき。CSV 用に全行も返す）
│           ├── inventory.py     # 機器台帳の自動取得（機種ごとのコマンドと show version などの読み取り）
│           ├── startup_check.py # 保存し忘れの検出（startup-config と running-config の比較）
│           ├── device_import.py # 機器の CSV 一括登録（文字コードの判別・列の対応・行ごとの検証）
│           ├── activity.py      # アクティビティログの記録とイベントの一覧
│           ├── audit.py         # 操作履歴の記録・ターミナルの記録（asciicast とテキスト）・保持期間
│           ├── terminal_text.py # ターミナルの画面出力を読めるテキストに直す（制御文字・打ち直しの跡を除く）
│           ├── login_limit.py   # ログインの失敗回数の制限（Redis。不正な API トークンも接続元の回数に数える）
│           ├── api_tokens.py    # API トークンの生成・照合（SHA-256）・失効・最後に使った日時・掃除
│           ├── system.py        # システムの状態の確認と、異常の検出・通知（ウォッチドッグ）
│           ├── mail.py          # メールの組み立て・SMTP での送信・OAuth 2.0 のトークン（Microsoft 365・Google）
│           ├── notify.py        # 通知（変更・違反・収集失敗・機器情報・Ping監視）の宛先の決定・Discord / Slack / Teams・メールへの送信（Teams の URL の検査・Adaptive Card もここ）
│           ├── report.py        # 定期レポート（週次・月次）の集計・本文・送る日の判定・二重送信の防止（report_sends）
│           ├── ping.py          # ICMP 送信（icmplib）・名前解決・一定間隔の実行
│           ├── git_export.py    # コンフィグ履歴を外部 Git（GitLab / Gitea）へ push（書き出し用のリポジトリの更新・認証・失敗の説明）
│           ├── ping_monitor.py  # Ping監視の常時監視（worker から実行。結果の記録・応答なし / 復旧の判定・推移の集計）
│           ├── monitoring.py    # SNMP（pysnmp）での帯域の取得・bps の計算・記録の保存と削除
│           ├── fw_hits.py       # FW ルールのヒット数の取得と読み取り（PAN-OS・FortiGate）
│           ├── vuln_fetch.py    # 脆弱性・サポート終了日の外部からの取得（宛先の許可リスト・上限・解析。外部へつなぐのはここだけ）
│           ├── vuln_match.py    # OS バージョンの分解（機種ごと）と影響範囲との照合（純粋な関数）
│           ├── vuln_service.py  # 取得の実行と保存・機器との照合と判定の移り変わり・サポート終了日の引き当て
│           ├── profile_access.py # 認証情報プロファイルを誰が編集・使用できるか（所有者とユーザーグループ）
│           └── connection.py    # 接続情報（踏み台含む）の読み出し・認証情報（機器 / プロファイル）の決定
└── frontend/
    ├── Dockerfile               # dev / prod マルチステージ
    ├── build-ca/                # ビルド用の追加の CA の写し（backend と同じ。npm ci・apk upgrade の間だけ使う）
    ├── nginx/                   # 本番用 nginx 設定（HTTP / HTTPS を起動時に自動選択・セキュリティヘッダー。CSP の値は csp.inc）
    ├── package.json
    ├── package-lock.json
    ├── tsconfig.json
    ├── vite.config.ts
    ├── e2e/                     # 画面テスト（Playwright の設定・初期データ・テスト。CSP の確認は csp.spec.ts と vite.csp.config.ts）
    └── src/
        ├── main.tsx
        ├── App.tsx              # ルーティング・ログインガード・画面の遅延読み込み・左ペインのメニュー（大項目・小項目）
        ├── index.css
        ├── auth.tsx             # ログインユーザー・権限（useAuth / RequirePerm）
        ├── platforms.ts         # 対応プラットフォーム一覧の取得（usePlatforms）
        ├── api/client.ts        # Axios クライアント・認証
        ├── topology/            # 構成図（React Flow のノード・接続線・保存形式の変換）
        ├── components/
        │   ├── CsvButton.tsx    # CSV・ファイルのダウンロード（監査ログ・アクティビティ・世代管理）
        │   ├── DeviceImportModal.tsx # 機器の CSV 一括登録（内容の確認 → 登録）
        │   ├── MailServerTab.tsx # 通知設定の「メールサーバー」（SMTP Auth・OAuth 2.0 の設定・テストメール）
        │   ├── BaselineModal.tsx # 基準にする・解除するモーダル・「基準」のバッジ（世代管理・変更の確認で共通）
        │   ├── StartupDiffModal.tsx # 保存されていない変更（startup → running の差分）のモーダル
        │   ├── MfaModal.tsx     # 2 段階認証の設定（QR コード・確認・予備コード・解除）
        │   ├── ApiTokenModal.tsx # API トークンの一覧・発行（値は発行直後に 1 回だけ表示）・失効
        │   └── ReviewModal.tsx  # 変更の確認のモーダル・状態のバッジ（変更の確認・世代管理で共通）
        └── pages/
            ├── LoginPage.tsx    # ログイン（2 段階認証の確認コードの入力を含む）
            ├── DevicesPage.tsx  # デバイス管理
            ├── JumpHostsPage.tsx # 踏み台サーバ
            ├── CredentialProfilesPage.tsx # 認証情報プロファイル
            ├── CollectPage.tsx  # コンフィグ収集
            ├── CommandsPage.tsx # コマンド実行（機器の選択・コマンド入力と検証・進み具合・機器ごと / 同じ出力ごとの結果・保存・過去の実行）
            ├── HistoryPage.tsx  # 世代管理・差分・別の機器との比較・ダウンロード・変更へのコメント・確認のバッジ・基準の世代
            ├── ReviewsPage.tsx  # 変更の確認（変更の一覧・確認済み / 想定外を付ける / 基準からのずれ。タブで機能を足せる構成）
            ├── TerminalPage.tsx # SSH ターミナル
            ├── SchedulePage.tsx # スケジュール
            ├── TopologyPage.tsx # 構成図
            ├── CompliancePage.tsx # コンプライアンス
            ├── IgnoreRulesPage.tsx # 無視する行（機種・機器ごとの正規表現・試す。管理者のみ）
            ├── ActivityPage.tsx # アクティビティ（システムで起きたこと）
            ├── AuditPage.tsx    # 監査ログ（操作履歴・ターミナルの記録の再生）
            ├── PingPage.tsx     # Ping監視（deadman 風。リアルタイム / 常時監視のタブ）
            ├── PingMonitorPanel.tsx # Ping監視の常時監視（対象の追加・状態・推移のグラフ）
            ├── SystemPage.tsx   # システム状態（worker・スケジューラー・収集の状況・ディスク・証明書・外部への接続）
            ├── DashboardPage.tsx # ダッシュボード（ログイン後の最初の画面）
            ├── SearchPage.tsx   # コンフィグ検索（全機器の最新コンフィグ・過去の世代の横断検索・機種での絞り込み・CSV 出力）
            ├── MonitoringPage.tsx # モニタリング（帯域のグラフ・FW ルールのヒット数・SNMP 設定）※試験導入
            ├── VulnsPage.tsx    # 脆弱性・サポート期限（一覧・機器別・サポート期限の手入力・判定できない機器）
            ├── NotificationsPage.tsx # 通知設定（自分・ユーザーグループ）
            └── UsersPage.tsx    # ユーザー管理（API トークンの数・全失効を含む）
```

---

## 今後の拡張ポイント

- **脆弱性・サポート期限の拡張（J-2 の予定）**: Fortinet の勧告（FortiGuard）、NVD による「候補」（Palo Alto・Fortinet 以外の機種。CPE が付いていない CVE は照合できない）、新しく該当したときの通知（`NotificationSetting.on_vuln`）・サポート終了日の事前通知（180・90・30 日前と当日）、ダッシュボードのタイル、定期レポートの節。Cisco の脆弱性情報は登録制の API（Cisco PSIRT openVuln）が必要なため対象外です（登録して `VULN_*` の鍵を設定する形で追加できます）。機器のカードへの表示、機能の設定（特定の機能を使っている機器だけ）まで見た絞り込み
- **イメージの更新の通知の拡張**: Dependabot（`.github/dependabot.yml`）は導入済み。nginx の安定版が切り替わったとき（1.30 → 1.32 など）に、`NGINX_MIN`（CI）と合わせて追従する手順の自動化、`audit.yml` のサービス用イメージ（`redis:7-alpine`）の更新の通知、PR を自動で取り込む設定（今は人が確認して取り込む）
- **導入スクリプトのテストの拡張**: `setup.sh` を偽のコマンドで通すテスト（`test_setup_script.py`）は導入済み。実機の AlmaLinux・Ubuntu での導入・更新の確認（コンテナの起動・再起動後の自動起動）、ルート以外の所有者のリポジトリを `sudo -u` で更新する分岐、`--reconfigure` の入力の組み合わせ、`restore.sh`・`import_cert.sh` を同じ作りで通すテスト
- **認証強化**: LDAP/AD 連携、2 段階認証の必須化（ロールごと）、機器グループ単位の権限、ログイン中の端末（セッション）の一覧と個別の切断、複数プロセス構成でのターミナルの強制切断（Redis 経由の通知など）
- **通知機能の拡張**: Teams の実環境での確認と、Teams 宛の本文の改良（Adaptive Card の色・列の表示、特定の人へのメンション）、Teams のチャネルへ直接送る Graph API 方式（アプリ登録が必要）、メールの Microsoft Graph（HTTPS）での送信（SMTP のポートを開けられない環境向け）、クライアントシークレットの期限の通知
- **定期レポートの拡張**: 集計を期間ごとに 1 回だけ集めて設定ごとの範囲をメモリで絞る作り直し（設定が多いとき）、PDF / CSV の添付、任意の期間（日付を指定したレポート）、ユーザーグループの設定のプレビュー・「いま送る」、期間内の件数を履歴として残していない項目（基準のずれ・保存し忘れ・未確認の変更）の推移、レポートごとの項目の選択
- **バックアップの拡張**: S3 などへの転送の組み込み（今は `BACKUP_POST_COMMAND` で対応）、公開鍵での暗号化（age など。サーバーに復号の鍵を置かない形）
- **パスワード管理**: HashiCorp Vault 連携
- **踏み台の多段化**: 2段以上の踏み台経由（現在は1段まで）
- **認証情報プロファイルの拡張**: 踏み台サーバへの適用、選んだ機器をまとめてプロファイルへ付け替える操作、プロファイルを使っている機器の一覧表示、プロファイルでの接続テスト、既存の機器の個別の認証情報からのプロファイル化
- **Ping監視の拡張**: 踏み台経由の PING、構成図への死活状態の表示、記録を時間ごとにまとめて長く残す
- **対応プラットフォーム**: 旧 CentreCOM（AlliedWare）・NEC IX・ALAXALA など Netmiko にドライバーの無い機種（独自ドライバーの追加が必要）
- **構成図の自動生成**: LLDP / CDP の隣接情報から接続線を自動作成（現在は手動作成）
- **無視する行の拡張**: 機器グループ単位のルール、過去の世代への適用（過去の世代は変えない方針のまま）、ルールごとの「何行消したか」の実績表示、ルールのひな形（時刻・カウンタなどよくある行）
- **世代の比較の拡張**: 機器ごとに違って当然の行（hostname・管理 IP など）を除いた比較、左右に並べた差分表示、差分そのもののダウンロード
- **変更の確認の拡張**: 想定外を付けたときの通知、承認ワークフロー（確認者と作業者を分ける・複数人の承認）、最初の世代（初回の収集）の確認、確認の履歴（付け直しの経緯）の画面表示（今は監査ログのみ）
- **保存し忘れの検出の拡張**: 実機での出力の確認と機種の追加（Junos の `show configuration` と commit 済みの差・PAN-OS・FortiGate は概念が違うため別の仕組みが必要）、保存し忘れが続いている日数の表示、機器の一覧での絞り込み、画面からの保存の実行（`write memory` を送る操作。今は読み取り専用）
- **基準の世代の拡張**: 機種・機器グループ共通の基準（ひな形）、ずれの自動修正（基準へ戻すコンフィグの投入）、ずれた行の内容の要約表示、基準の履歴（付け替えの経緯）の画面表示（今は監査ログのみ）、ずれが続いている日数の表示
- **左ペインのメニューの拡張**: 大項目の並べ替え・ユーザーごとの表示の選択、すべて開く／閉じる操作、メニュー内の検索、画面の幅が狭いときの折りたたみ（今は幅 200px 固定）
- **変更へのコメントの拡張**: コメントの無い変更の一覧（説明の付いていない変更の洗い出し）、コメントでの検索、コメントが付いたときの通知
- **モニタリング（試験導入）の本採用**: 既定を有効に切り替え。使用率のしきい値超えの通知、構成図の接続線への使用率の表示、FortiGate の VDOM・PAN-OS の複数 vsys 対応、他機種（Cisco ASA など）のヒット数
- **コンプライアンスの検査の非同期化**: ルールの作成・更新の直後の全機器の検査（照合）が API のイベントループの上で動くため、機器が多いと応答が遅れる。スレッドか worker へ移す
- **CSV 一括登録の拡張**: 既存の機器の CSV による更新（上書き）、SSH 鍵での一括登録、未登録のグループの自動作成、タブ区切り（TSV）の貼り付け
- **Ubuntu 24.04 LTS の実機での確認と対応 OS の拡張**: 実機での導入・更新の確認（「Ubuntu 24.04 LTS で使う」の確認項目）、Podman・podman-compose の版の差で出た問題の吸収、Debian 12 の確認、ユニットそのものが無い環境への `podman-restart.service` の自動配置、RHEL 系の `podman-restart.service` が `unless-stopped` のコンテナを起動するかの本番での確認、Ubuntu の `podman-compose` を新しい版へ上げる手順
- **コマンド実行の拡張**: MikroTik RouterOS への対応（メニュー名の許可リスト方式で対応する想定）、スケジュール実行（定期的に `show` を取って比べる）、設定の投入（承認・確認の仕組みとセットで）、時刻・カウンタなど毎回変わる部分を除いた「同じ出力」のまとめ、機器グループ単位の権限、実機での機種ごとの許可リストの確認（Yamaha・NetScaler・Nokia などの絞り込み）、出力が大きいときの分割取得（今は 1 回の応答にまとめて返す）、失敗したコマンドまでの出力の保持（今は 1 台の接続が途中で失敗するとその機器の出力は残らない）
- **コンフィグ検索の拡張**: 世代の多い環境向けに過去の世代の検索を Celery のタスクにして結果を後で受け取る形、登録済みの機器がある機種だけを選択肢にする
- **API トークンの拡張**: 権限を細かく選べるトークン（API・機器グループごと）、接続元 IP の制限、期限が近いトークンの通知、`/docs`・`/openapi.json` の公開範囲の見直し（今はログインなしで見られる）、トークンで使える API の拡大（認証情報を扱う操作を、別の確認の仕組みとセットで）
- **導入・更新のプロキシの拡張**: 秘密を compose の `environment:` ではなく `env_file:` で渡す形への移行（`podman run` の引数・プロセスの一覧に出なくなる。既存の秘密すべてに及ぶ）、`setup.sh` だけをダウンロードした初回の clone での追加の CA、AlmaLinux 10（Podman 5・SELinux）の実機での確認
- **CSP の強化**: 違反をブラウザから受け取って記録する仕組み（`report-to`）、`style-src 'unsafe-inline'` の撤廃（ターミナルの xterm.js などがノンスに対応したら）、HSTS の期間の延長（証明書の更新が安定したら）
