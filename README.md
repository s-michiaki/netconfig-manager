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
| Ping監視 | icmplib + WebSocket | 登録機器・指定IPへの死活監視（deadman 風） |
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

収集時、タイムスタンプなど取得のたびに変わる行（`! Last configuration change at ...` 等）は除外してから保存するため、実際に設定が変わったときだけ新しい世代が作られます。除外パターンは `backend/app/services/config_service.py` の `PLATFORMS` で調整できます。

ページング（`--More--` 等）はログイン時に自動で無効化します（`terminal length 0` / `screen-length` / `set cli pager off` / `console lines infinity` 等）。権限不足などで無効化できず出力が途中で止まった場合は、タイムアウトを待たずに収集エラーとし、不完全なコンフィグは保存しません。

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
- `certs/`（Git 管理外）に `server.crt`・`server.key`（600）・`ca.crt` として配置し、`.env` の `HTTPS_PORT` と firewalld を設定して nginx を再起動します。差し替え前の証明書は `/root/netconfig-manager-backup/certs-<日時>/` に退避します
- HTTPS 対応前の構成で動いている場合は、コンテナを作り直します（`setup.sh` と同じ。DB・コンフィグ履歴は保持）
- 証明書を再発行したときも、同じスクリプトをもう一度実行してください
- 証明書が読み込めない状態で起動した場合は、画面に入れなくならないよう HTTP で起動します（nginx のログに理由を出力）
- HTTP に戻す場合は `certs/server.crt`・`certs/server.key` を削除して frontend コンテナを再起動

**利用者の PC にルート CA を登録**（初回のみ。登録しないとブラウザが証明書の警告を出します）

1. `http://<サーバー>/ca.crt` からルート CA をダウンロード（取り込み時に `ca.crt` を指定した場合のみ配布）
2. スクリプトが表示した SHA256 指紋と一致するか確認
3. Windows: 管理者の PowerShell で `Import-Certificate -FilePath .\netconfig-root-ca.crt -CertStoreLocation Cert:\LocalMachine\Root`（またはファイルをダブルクリック →「証明書のインストール」→ ローカルコンピューター →「信頼されたルート証明機関」）
4. ホスト名（例: `www.sameshima.test`）で開く場合は、DNS か hosts ファイルにサーバーの IP を登録

### バックアップと復元

`setup.sh` が systemd タイマー（`netconfig-backup.timer`）を登録し、毎日 `scripts/backup.sh` でバックアップを取ります。

- **内容**: DB（`pg_dump`）・コンフィグ履歴（機器ごとの Git リポジトリ）・SSH の known_hosts・ターミナルの記録・`.env`・証明書（`certs/`）を1つのファイル `netconfig-backup-<日時>.tar.gz` にまとめます
- **保存先**: `/var/backups/netconfig-manager/`（root だけが読める）。`.env` の `BACKUP_DIR` で変更できます。サーバーの故障に備えて、別ディスク・NFS など**サーバーの外**にも置いてください
- **保存期間**: `BACKUP_KEEP_DAYS`（既定 14 日）より古いものを削除します（最新の1つは必ず残します）
- **実行時刻**: `BACKUP_ON_CALENDAR`（systemd の OnCalendar 形式。既定 `*-*-* 03:15:00`、`off` で無効）。変更後は `setup.sh` を実行すると反映されます
- ターミナルの記録を含めない場合は `BACKUP_TERMINAL_LOGS=false`
- バックアップには `.env`（`DEVICE_ENCRYPTION_KEY`）が含まれ、機器のパスワードを復号できます。持ち出すときは取り扱いに注意してください

```bash
sudo bash /opt/netconfig-manager/scripts/backup.sh          # 今すぐ実行
sudo bash /opt/netconfig-manager/scripts/backup.sh --list   # 一覧
systemctl list-timers netconfig-backup.timer                # 次回の実行
journalctl -u netconfig-backup.service                      # 実行結果
```

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

## 機器への SSH 認証

機器ごとにパスワード・SSH 秘密鍵のどちらか、または両方を設定できます（直接接続・踏み台経由のどちらでも使えます）。

- 秘密鍵は OpenSSH 形式（`-----BEGIN OPENSSH PRIVATE KEY-----`）または PEM 形式の RSA / ECDSA / Ed25519。パスフレーズ付きの鍵も使えます
- 両方を設定した場合は鍵 → パスワードの順に試します
- 秘密鍵・パスフレーズは暗号化して保存し、画面・API には鍵の種類と指紋のみ表示します
- Cisco 等で enable が必要な場合は、鍵認証でも「Enableシークレット」を設定してください

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
  - PDF のライブラリ（jsPDF）は書き出すときだけ読み込みます
- 編集は「編集」ボタンで開始し、「保存」で確定します。他のユーザーが先に保存していた場合は上書きせずにエラーになります（再読み込みしてから編集し直してください）
- 編集中は ↶（取り消す・Ctrl+Z）/ ↷（やり直す・Ctrl+Shift+Z / Ctrl+Y）で操作を戻せます（移動・追加・削除・線の接続・大きさや設定の変更。同じ項目への続けての入力は1回分にまとめます。最大100回）。保存・「変更を破棄」・編集の終了で履歴はリセットされます。文字の入力欄では、その欄の取り消しが優先されます
- 機器を削除すると、その機器は構成図からも取り除かれます（つながっていた線も削除）

## コンプライアンスチェック

「コンプライアンス」画面で検査ルールを登録すると、収集したコンフィグを自動で検査し、違反を一覧表示します。

- ルールは「一致する行が必要 / あってはいけない」×「文字列を含む / 正規表現」で、1行ずつ判定します
- 範囲は「コンフィグ全体」か「セクションごと」。セクションは行頭に空白の無い行を見出し、続く字下げされた行を中身とします（例: 見出し `^interface GigabitEthernet` の各セクションに `description` が必要）
- 対象のプラットフォームを絞れます（未選択なら全機種）。重要度は高・中・低
- 検査のタイミング: 収集に成功したとき（その機器）、ルールを作成・変更したとき・「全機器を再検査」を押したとき（全機器）、種類「コンプライアンスチェック」のスケジュール（下記）
- **定期的な検査**: 「スケジュール設定」で種類に「コンプライアンスチェック」を選ぶと、機器には接続せず、収集済みの最新のコンフィグを Cron 式の時刻に検査し直します（対象は全機器・グループ・機器を選べます）。収集の頻度が低い機器の再確認や、期限切れになった例外の反映に使います。結果（検査した台数・新しい違反・解消の件数）はアクティビティログに残ります
- ルール編集画面の「試す」で、保存前に機器の最新のコンフィグで判定結果を確認できます
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

「Ping監視」画面で、登録済みの機器と指定した IP アドレス / ホスト名に一定間隔で PING し、応答状況をリアルタイムに表示します（deadman 風）。

- **対象**: 登録機器（デバイス設定の「ホスト」のアドレス）と、「IP を追加・管理」で登録した IP / ホスト名（ゲートウェイ・DNS・サーバーなど機器以外の宛先）
- **表示**: 機器のグループごとに、状態・損失率・送信/受信数・最新/平均/最小/最大の応答時間・最終応答からの経過時間・直近60回の履歴（棒の高さ＝応答時間、赤＝応答なし）。応答なしの行は赤く点滅します
- 「対象を選ぶ」でグループ単位・個別に監視対象を選べます（選択と間隔はブラウザに保存）。間隔は 1 / 2 / 5 / 10 秒
- 「異常のみ表示」で、応答なし・損失あり・名前解決失敗の対象だけを表示
- 統計は画面で集計しており、画面を離れる・「統計リセット」でリセットされます（履歴の保存やアラート通知はしません）
- PING は**サーバーから**送信します。踏み台の先にある機器など、サーバーから直接届かない宛先は「応答なし」になります
- 画面からは登録済みの対象しか指定できません（任意のアドレスへの PING にサーバーを使わせないため、アドレスはサーバー側で引き当てます）
- ICMP の送信には backend コンテナに `NET_RAW` 権限と `net.ipv4.ping_group_range` の設定が必要です（docker-compose に設定済み）
- `.env` の `PING_TIMEOUT`（1回の応答待ち、既定 1 秒）・`PING_MAX_TARGETS`（同時に監視できる対象数、既定 300）で調整できます
- 利用は閲覧者以上、IP の追加・編集・削除はオペレーター以上。追加・変更・削除は監査ログに残ります

## 通知（Discord / Slack）

コンフィグの変更・コンプライアンス違反の発生・収集の失敗を、Discord・Slack の Webhook に通知します。「通知設定」画面で設定します。

- **通知する内容**（通知設定ごとに選択。既定はコンフィグの変更のみ）
  - コンフィグの変更: 収集で設定の変更が見つかったとき
  - コンプライアンス違反の発生: 新しく違反になったとき（解消・除外は通知しません）。機器名・違反したルールと重要度、違反一覧へのリンク。ルールの追加などで多数の機器が同時に違反になったときは、通知先ごとに1通にまとめます
  - 収集の失敗: 再試行しても収集できなかったとき（認証失敗など再試行しないものはすぐ）。機器名・エラー・アクティビティへのリンク

- **変更通知の内容**: 機器名・IP・機器のグループ・変更行数（+n / -n）・収集の種類と時刻・世代と、差分画面へのリンク。差分の中身（パスワードのハッシュ等を含みうる）は送りません
- **自分の通知**（全ユーザー）: 次のどれかを選びます
  - 所属グループの設定を使う（既定）: 所属するユーザーグループのうち、通知が有効なものの通知先・対象で通知
  - 個別に設定する: 自分の Webhook と、通知する機器のグループ（すべて / 選択したグループ / 未分類）を指定
  - 通知しない
- **ユーザーグループ**（管理者）: チームを作ってメンバーを登録し、グループの通知先・対象を設定します。1人が複数のグループに所属できます
- 同じ Webhook へは1回だけ送ります（グループの Webhook はメンバーが何人いても1回）。「所属グループの設定を使う」メンバーがいないグループの Webhook には送りません
- 初回の取得は変更ではないため通知しません。通知の送信は収集とは別のタスクで行い、失敗しても収集には影響しません
- 「テスト通知を送る」で通知先を確認できます。最後の送信結果（失敗時は理由）も表示します
- 管理者は「通知先の確認」で、機器のグループと通知の内容ごとにどこへ送られるかを確認できます
- Webhook URL は暗号化して保存し、画面では末尾4文字だけ表示します。宛先は Discord（`https://discord.com/api/webhooks/…`）・Slack（`https://hooks.slack.com/…`）の公式 URL に限ります
- リンク先は `.env` の `PUBLIC_URL`（例: `https://192.168.1.10`）。`setup.sh`・`import_cert.sh` が未設定のときに IP アドレスから設定します。空ならリンクなしで送ります
- サーバーから Discord・Slack（インターネット）へ HTTPS で接続できる必要があります
- 設定の変更・テスト通知・ユーザーグループの変更は監査ログに残ります

## アクティビティ（システムで起きたことの記録）

「アクティビティ」画面で、システムで起きた出来事を確認できます（閲覧者以上）。利用者の操作は「監査ログ」、処理の結果・出来事はこちら、と分けています。

| 種類 | 記録する出来事 |
|---|---|
| 収集 | 変更あり（+n / -n 行・世代）／変更なし／初回取得／失敗（再試行する場合は警告、最終的な失敗はエラー）／実行中のためスキップ／一括収集の開始 |
| スケジュール | スケジュールの実行（種類・対象）、Cron 式が不正で実行できないとき（1時間に1回まで） |
| コンプライアンス | 違反の発生・解消・例外による除外・例外の期限切れ（機器・ルール・重要度・該当箇所）、スケジュールでの検査の結果（台数・新しい違反・解消の件数）。ルールの追加などで一度に 30 件を超えて変わったときは1件にまとめる |
| 通知 | 変更・違反・収集失敗の通知の送信と失敗（送信先の種類と誰の設定か。URL は残さない） |
| システム | 保持期間を過ぎたログの削除 |

- 「きっかけ」には、手動の収集なら実行したユーザー名、スケジュールなら「スケジュール「名前」」、自動処理なら「システム」を記録します
- 種類・重要度（情報・警告・エラー）・機器・キーワード・期間で絞り込めます。行をクリックすると詳細（世代へのリンク・違反箇所など）を表示します
- 監査ログの「収集の実行」の行にある「収集の結果を見る」から、その実行の結果（各機器の収集・違反・通知）だけを表示できます（一括収集・スケジュールは配下の機器の記録をまとめて表示）
- 「CSV 出力」で、今の絞り込み条件のまま CSV に書き出せます（形式は監査ログの CSV 出力と同じ。出力したことは監査ログに残ります）
- 保持期間は `.env` の `ACTIVITY_LOG_RETENTION_DAYS`（既定 90 日、0 で無期限）。スケジュール収集の「変更なし」で件数が増えるため、不要なら `ACTIVITY_LOG_UNCHANGED=false` で記録しないようにできます

## 監査ログ

管理者は「監査ログ」画面で、誰が・いつ・何をしたかを確認できます。

- **操作履歴**: ログイン（失敗を含む）、パスワード変更、ユーザー・機器・踏み台・スケジュール・構成図・コンプライアンスのルールと例外・Ping監視の対象の変更、収集の実行、ターミナルの接続・切断、ターミナル記録の閲覧、監査ログ・アクティビティログの CSV 出力。パスワードや秘密鍵の値は残さず「変更した」ことだけを記録します
- **ターミナルの記録**: SSH ターミナルの画面出力をセッションごとに記録し、画面上で再生できます（asciicast v2 形式。`.cast` としてダウンロードして asciinema でも再生可）
  - キー入力そのものは記録しません（enable のパスワードなど画面に表示されない入力が含まれるため）。入力したコマンドは機器のエコーとして画面出力に残ります
  - 記録は `terminal_logs` ボリューム（`/data/terminal-logs`）に保存。1セッションの上限は 20MB（`TERMINAL_LOG_MAX_BYTES`）
  - 記録は `DEVICE_ENCRYPTION_KEY` で暗号化して保存します（`.cast.enc`。画面出力に show running-config の内容などが残るため）。閲覧・ダウンロード時にサーバーで復号します。`TERMINAL_LOG_ENCRYPT=false` で従来どおり平文（`.cast`）
  - v1.23.0 より前の平文の記録は保持期間で消えるまでそのまま読めます。すぐ暗号化する場合は `sudo podman exec netconfig-manager_backend_1 python -m app.tools.encrypt_recordings`（コンテナ名は `podman ps` で確認）
  - `DEVICE_ENCRYPTION_KEY` を変えると過去の記録は読めなくなります（機器のパスワードと同じ）
- **CSV 出力**: 操作履歴・ターミナルの記録（接続の一覧）を、画面の絞り込み条件のまま CSV で出力できます（「CSV 出力」ボタン。新しい順に最大10万件）
  - Excel でそのまま開けるよう BOM 付き UTF-8。日時はサーバーのタイムゾーン（`TIMEZONE`）で出力します
  - `=` などで始まる値は、表計算ソフトで数式として実行されないよう先頭に `'` を付けます
  - ターミナルの画面の記録そのものは含みません（再生画面から `.cast` でダウンロード）。出力したこと自体も操作履歴に残ります
- **保持期間**: `.env` の `AUDIT_LOG_RETENTION_DAYS`（既定 365 日）・`TERMINAL_LOG_RETENTION_DAYS`（既定 180 日）。毎日1回、期限切れのものを削除します（0 で無期限）

## ユーザーと権限（RBAC）

ユーザーには3つのロールのいずれかを割り当てます。ユーザーの追加・ロール変更・無効化・パスワードリセットは、管理者が「ユーザー管理」画面から行います。

| 権限 | 閲覧者 (viewer) | オペレーター (operator) | 管理者 (admin) |
|---|:-:|:-:|:-:|
| デバイス閲覧 | ✓ | ✓ | ✓ |
| コンフィグ・差分閲覧 | ✓ | ✓ | ✓ |
| スケジュール閲覧 | ✓ | ✓ | ✓ |
| 構成図の閲覧 | ✓ | ✓ | ✓ |
| コンプライアンスの結果・ルールの閲覧 | ✓ | ✓ | ✓ |
| Ping監視の利用 | ✓ | ✓ | ✓ |
| 変更通知（自分の通知設定） | ✓ | ✓ | ✓ |
| アクティビティ（収集の結果・違反の発生など）の閲覧 | ✓ | ✓ | ✓ |
| 収集の実行 | | ✓ | ✓ |
| SSHターミナル | | ✓ | ✓ |
| 構成図の作成・編集・削除 | | ✓ | ✓ |
| コンプライアンスのルール編集・例外の登録・再検査 | | ✓ | ✓ |
| Ping監視の対象 IP の追加・編集・削除 | | ✓ | ✓ |
| デバイス登録・編集・削除 | | | ✓ |
| スケジュール編集 | | | ✓ |
| ユーザー管理・ユーザーグループ（変更通知のチーム）の管理 | | | ✓ |
| 監査ログの閲覧・CSV 出力 | | | ✓ |

- 割り当ては `backend/app/core/permissions.py` の `ROLE_PERMISSIONS` だけで定義しています。変更する場合はここを編集してください（画面の表示も `/api/auth/me` が返す権限に従って自動で切り替わります）
- 権限チェックはすべてサーバー側で行います。新しいAPIを追加するときは `dependencies=[Depends(require(Perm.XXX))]` を付けてください（付け忘れはテスト `test_every_protected_route_declares_a_permission` で検出されます）
- ロールの変更・無効化は即座に反映されます（ログイン中のユーザーにも次のリクエストから適用）
- パスワードの変更・リセットを行うと、それ以前に発行されたトークンは無効になります
- 自分自身のロール変更・無効化・削除はできません（有効な管理者が1人もいなくなる操作も拒否されます）
- 操作の記録は「監査ログ」画面で確認できます（管理者のみ）

## セキュリティ

- **認証**: `/api/auth/token` と `/api/health` 以外の API はすべてログインが必要です。WebSocket ターミナルは接続直後のメッセージでトークンを検証し、ターミナル権限が無ければ切断します
- **機器パスワード**: DB には Fernet で暗号化して保存します。旧バージョンで平文保存されていたものは backend 起動時に自動で暗号化されます
- **SSHホスト鍵**: known_hosts を `ssh_data` ボリューム（`/data/ssh/known_hosts`）で backend と worker が共有します
  - `tofu`: 初回接続時に鍵を記録し、以後は一致しなければ接続を拒否（機器を入れ替えた場合は known_hosts から該当行を削除）
  - `strict`: known_hosts に事前登録したホストにのみ接続
- **収集したコンフィグ**: パスワードハッシュや SNMP コミュニティ等が含まれるため、`config_repo` ボリュームのアクセス権・バックアップ先の扱いに注意してください
- **ターミナルの記録**: 機器の画面出力（show running-config の結果など）がそのまま残るため、`terminal_logs` ボリュームも同様に扱ってください。閲覧は管理者のみで、閲覧したこと自体も操作履歴に残ります

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

リンター（ruff。設定は `backend/ruff.toml`）:

```bash
cd backend
ruff check .          # 指摘の確認
ruff check --fix .    # 自動で直せるものを修正
```

GitHub に push すると、GitHub Actions（`.github/workflows/ci.yml`）が自動で次を実行します（結果はリポジトリの「Actions」タブで確認）:

- backend: ruff と pytest（Python 3.12）
- frontend: `npm ci` → 型チェック（tsc）→ 本番ビルド（vite build）（Node.js 20）

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
├── docker-compose.yml           # 開発用
├── docker-compose.prod.yml      # 本番用（nginx 配信）
├── .env.example
├── certs/                       # HTTPS の証明書（import_cert.sh で配置。Git 管理外）
├── scripts/
│   ├── setup.sh                 # 自動セットアップ・更新
│   ├── check_env.sh             # 導入前チェック
│   ├── import_cert.sh           # HTTPS 化（証明書の取り込み）
│   ├── backup.sh                # バックアップ（setup.sh が毎日実行するよう登録）
│   └── restore.sh               # バックアップからの復元
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── requirements-dev.txt     # テスト用
│   ├── alembic.ini              # DBマイグレーション設定
│   ├── migrations/versions/     # マイグレーション
│   ├── tests/                   # pytest
│   ├── ruff.toml                # リンター（ruff）の設定
│   └── app/
│       ├── main.py              # FastAPI エントリーポイント・起動時の移行処理
│       ├── worker.py            # Celery タスク定義（収集・スケジュール実行・定期コンプライアンスチェック）
│       ├── tools/
│       │   └── encrypt_recordings.py  # 既存の平文のターミナル記録を暗号化（podman exec で実行）
│       ├── core/
│       │   ├── config.py        # 設定
│       │   ├── database.py      # DB セッション
│       │   ├── security.py      # パスワードハッシュ・JWT
│       │   ├── permissions.py   # ロールと権限の定義（RBAC）
│       │   ├── crypto.py        # 機器パスワード暗号化
│       │   ├── csv_export.py    # CSV 出力の共通処理（監査ログ・アクティビティ）
│       │   ├── ssh_hostkeys.py  # SSH ホスト鍵検証
│       │   ├── ssh_keys.py      # SSH 秘密鍵の読み込み（機器・踏み台共通）
│       │   ├── ssh_jump.py      # 踏み台経由の接続
│       │   └── migrate.py       # 起動時のDBマイグレーション
│       ├── models/
│       │   ├── __init__.py      # モデル登録
│       │   ├── base.py
│       │   ├── device.py        # Device / DeviceGroup / JumpHost / ConfigSnapshot / CollectLog / Schedule
│       │   ├── topology.py      # TopologyMap（構成図）
│       │   ├── compliance.py    # ComplianceRule / ComplianceResult / ComplianceException
│       │   ├── activity.py      # ActivityLog（システムで起きたこと）
│       │   ├── audit.py         # AuditLog（操作履歴）/ TerminalSession（ターミナルの記録）
│       │   ├── notification.py  # UserGroup / UserGroupMember / NotificationSetting（通知）
│       │   ├── ping.py          # PingTarget（Ping監視で追加した IP）
│       │   └── user.py          # User
│       ├── api/
│       │   ├── deps.py          # 認証・権限チェック（require）
│       │   ├── auth.py          # ログイン・パスワード変更
│       │   ├── devices.py       # デバイス CRUD + 収集トリガー
│       │   ├── device_groups.py # 機器のグループ CRUD・所属の一括変更
│       │   ├── jump_hosts.py    # 踏み台サーバ CRUD + 接続テスト
│       │   ├── configs.py       # 履歴・差分 API
│       │   ├── tasks.py         # 収集タスクの状態確認
│       │   ├── users.py         # ユーザー管理（管理者のみ）
│       │   ├── terminal.py      # WebSocket SSH ターミナル
│       │   ├── topology.py      # 構成図 CRUD・機器の収集状態
│       │   ├── compliance.py    # コンプライアンスのルール・結果・例外・テンプレート
│       │   ├── activity.py      # アクティビティログの閲覧
│       │   ├── audit.py         # 監査ログの閲覧・CSV 出力（管理者のみ）
│       │   ├── notifications.py # 通知設定（自分）・ユーザーグループ・通知先の確認
│       │   ├── ping.py          # Ping監視の対象 CRUD・WebSocket で結果を配信
│       │   └── schedules.py     # スケジュール CRUD
│       └── services/
│           ├── config_service.py # 対応プラットフォーム（PLATFORMS）・Netmiko での収集・GitPython
│           ├── compliance.py    # コンプライアンスの評価エンジン（例外の適用を含む）
│           ├── activity.py      # アクティビティログの記録とイベントの一覧
│           ├── audit.py         # 操作履歴の記録・ターミナルの記録（asciicast）・保持期間
│           ├── notify.py        # 通知（変更・違反・収集失敗）の宛先の決定・Discord / Slack への送信
│           ├── ping.py          # ICMP 送信（icmplib）・名前解決・一定間隔の実行
│           └── connection.py    # 接続情報（踏み台含む）の読み出し
└── frontend/
    ├── Dockerfile               # dev / prod マルチステージ
    ├── nginx/                   # 本番用 nginx 設定（HTTP / HTTPS を起動時に自動選択）
    ├── package.json
    ├── package-lock.json
    ├── tsconfig.json
    ├── vite.config.ts
    └── src/
        ├── main.tsx
        ├── App.tsx              # ルーティング・ログインガード・画面の遅延読み込み
        ├── index.css
        ├── auth.tsx             # ログインユーザー・権限（useAuth / RequirePerm）
        ├── platforms.ts         # 対応プラットフォーム一覧の取得（usePlatforms）
        ├── api/client.ts        # Axios クライアント・認証
        ├── topology/            # 構成図（React Flow のノード・接続線・保存形式の変換）
        ├── components/
        │   └── CsvButton.tsx    # CSV のダウンロード（監査ログ・アクティビティ共通）
        └── pages/
            ├── LoginPage.tsx    # ログイン
            ├── DevicesPage.tsx  # デバイス管理
            ├── JumpHostsPage.tsx # 踏み台サーバ
            ├── CollectPage.tsx  # コンフィグ収集
            ├── HistoryPage.tsx  # 世代管理・差分
            ├── TerminalPage.tsx # SSH ターミナル
            ├── SchedulePage.tsx # スケジュール
            ├── TopologyPage.tsx # 構成図
            ├── CompliancePage.tsx # コンプライアンス
            ├── ActivityPage.tsx # アクティビティ（システムで起きたこと）
            ├── AuditPage.tsx    # 監査ログ（操作履歴・ターミナルの記録の再生）
            ├── PingPage.tsx     # Ping監視（deadman 風）
            ├── NotificationsPage.tsx # 通知設定（自分・ユーザーグループ）
            └── UsersPage.tsx    # ユーザー管理
```

---

## 今後の拡張ポイント

- **認証強化**: LDAP/AD 連携、MFA、機器グループ単位の権限
- **通知機能の拡張**: メール・Microsoft Teams への通知、一括収集で多数の機器が失敗したときのまとめ通知
- **バックアップの拡張**: config_repo を外部 Git サーバー (GitLab/Gitea) へ push、バックアップの外部ストレージ（S3 など）への転送
- **パスワード管理**: HashiCorp Vault 連携
- **踏み台の多段化**: 2段以上の踏み台経由（現在は1段まで）
- **Ping監視の拡張**: 結果の履歴保存・グラフ、応答なしが続いたときの通知、踏み台経由の PING、構成図への死活状態の表示
- **対応プラットフォーム**: 旧 CentreCOM（AlliedWare）・NEC IX・ALAXALA など Netmiko にドライバーの無い機種（独自ドライバーの追加が必要）
- **構成図の自動生成**: LLDP / CDP の隣接情報から接続線を自動作成（現在は手動作成）
