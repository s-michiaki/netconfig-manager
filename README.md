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
| Ping監視 | icmplib + WebSocket | 登録機器・指定IPへの死活監視（deadman 風） |
| タスクキュー | Celery + Redis | 非同期収集・定期収集（beat が毎分スケジュールを確認） |
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

---

## 機器のグループ

デバイス管理画面で、機器をグループ（拠点・用途など）ごとにまとめて表示できます。

- 「グループの管理」でグループを作成・名前変更・削除できます（複数作成可。色と説明も設定可）
- 機器は1つのグループにだけ所属します（どこにも属さない機器は「未分類」）。所属は機器の「編集」か、「選択してグループへ移動」で複数台まとめて変更します
- 表示は「グループ別」（グループごとに見出しを付けて表示・折りたたみ可）と「一覧」を切り替えられます。グループでの絞り込みと名前・IP での検索も可能（表示の設定はブラウザに保存）
- グループを削除しても機器は削除されず、未分類に戻ります
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
- 機器は右の「未配置の機器」からドラッグして配置します（1つの構成図に同じ機器は1回まで。別の構成図には何度でも置けます）
- 登録していない機器（ISPルーター・ハブ・PC など）は「＋ 非管理機器」で置けます。名前・補足（IP・型番など）・アイコンを自由に設定でき、破線の枠で表示します（収集・ターミナルの対象外）
- 機器の縁の ● から別の機器（非管理機器・雲を含む）へドラッグすると線を引けます。相手の箱の上ならどこで離してもつながります。線には両端のポート名・ラベル・線の種類（実線/破線）・色を設定できます。同じ2台の間に複数本引くと平行線で表示します
- 装飾として「雲」「テキスト」「グループ枠」を置けます（色・文字・大きさを変更可能）。グループ枠はラベル部分をドラッグして移動します
- 機器アイコンは最後の収集結果で色分けされます（緑: 成功 / 黄: 変更あり / 赤: 失敗 / 灰: 未収集）。状態は30秒ごとに自動更新
- 機器をクリックすると、ターミナル・変更履歴・今すぐ収集へ移動できます（ロールの権限に応じて表示）
- 論理構成では、自由に作図するための要素を追加できます
  - 図形（四角・角丸・楕円・ひし形）: 文字・塗り・枠線（実線/破線/点線）を設定。OSPF エリアや DMZ などの範囲を囲むのに使います
  - セグメント: VLAN・サブネットを表す線（横長・縦長）。線をつなぐとセグメント上に垂直に落ちます
  - 中継点: 線を折り曲げたり分岐させたりするための点
- 線は、物理・論理どちらでも矢印（片側/両側）・経路（直線/カギ線/曲線）・太さ・線種（実線/破線/点線）を設定できます
- 機器には補足（例: `Lo0 10.255.0.1`）を書けます。機器の下に表示されます
- 「PNG出力」で表示中の構成（物理/論理）全体を画像として保存できます
- 編集は「編集」ボタンで開始し、「保存」で確定します。他のユーザーが先に保存していた場合は上書きせずにエラーになります（再読み込みしてから編集し直してください）
- 機器を削除すると、その機器は構成図からも取り除かれます（つながっていた線も削除）

## コンプライアンスチェック

「コンプライアンス」画面で検査ルールを登録すると、収集したコンフィグを自動で検査し、違反を一覧表示します。

- ルールは「一致する行が必要 / あってはいけない」×「文字列を含む / 正規表現」で、1行ずつ判定します
- 範囲は「コンフィグ全体」か「セクションごと」。セクションは行頭に空白の無い行を見出し、続く字下げされた行を中身とします（例: 見出し `^interface GigabitEthernet` の各セクションに `description` が必要）
- 対象のプラットフォームを絞れます（未選択なら全機種）。重要度は高・中・低
- 検査のタイミング: 収集に成功したとき（その機器）、ルールを作成・変更したとき・「全機器を再検査」を押したとき（全機器）
- ルール編集画面の「試す」で、保存前に機器の最新のコンフィグで判定結果を確認できます
- 「テンプレートから追加」で、よく使う基準（SSH v2・Telnet 禁止・HTTP サーバー無効・SNMP コミュニティ・NTP、FortiGate の管理アクセス、AlliedWare Plus の Telnet / HTTP 無効化など）をまとめて登録できます
- 違反のある機器は構成図にも ⚠ と件数を表示します（色は最も重い違反の重要度）
- 閲覧は閲覧者以上、ルールの編集・再検査はオペレーター以上

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

## 監査ログ

管理者は「監査ログ」画面で、誰が・いつ・何をしたかを確認できます。

- **操作履歴**: ログイン（失敗を含む）、パスワード変更、ユーザー・機器・踏み台・スケジュール・構成図・コンプライアンスのルール・Ping監視の対象の変更、収集の実行、ターミナルの接続・切断、ターミナル記録の閲覧。パスワードや秘密鍵の値は残さず「変更した」ことだけを記録します
- **ターミナルの記録**: SSH ターミナルの画面出力をセッションごとに記録し、画面上で再生できます（asciicast v2 形式。`.cast` としてダウンロードして asciinema でも再生可）
  - キー入力そのものは記録しません（enable のパスワードなど画面に表示されない入力が含まれるため）。入力したコマンドは機器のエコーとして画面出力に残ります
  - 記録は `terminal_logs` ボリューム（`/data/terminal-logs`）に保存。1セッションの上限は 20MB（`TERMINAL_LOG_MAX_BYTES`）
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
| 収集の実行 | | ✓ | ✓ |
| SSHターミナル | | ✓ | ✓ |
| 構成図の作成・編集・削除 | | ✓ | ✓ |
| コンプライアンスのルール編集・再検査 | | ✓ | ✓ |
| Ping監視の対象 IP の追加・編集・削除 | | ✓ | ✓ |
| デバイス登録・編集・削除 | | | ✓ |
| スケジュール編集 | | | ✓ |
| ユーザー管理 | | | ✓ |
| 監査ログの閲覧 | | | ✓ |

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
├── docker-compose.yml           # 開発用
├── docker-compose.prod.yml      # 本番用（nginx 配信）
├── .env.example
├── certs/                       # HTTPS の証明書（import_cert.sh で配置。Git 管理外）
├── scripts/
│   ├── setup.sh                 # 自動セットアップ・更新
│   ├── check_env.sh             # 導入前チェック
│   └── import_cert.sh           # HTTPS 化（証明書の取り込み）
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
│       │   ├── device.py        # Device / DeviceGroup / JumpHost / ConfigSnapshot / CollectLog / Schedule
│       │   ├── topology.py      # TopologyMap（構成図）
│       │   ├── compliance.py    # ComplianceRule / ComplianceResult
│       │   ├── audit.py         # AuditLog（操作履歴）/ TerminalSession（ターミナルの記録）
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
│       │   ├── compliance.py    # コンプライアンスのルール・結果・テンプレート
│       │   ├── audit.py         # 監査ログの閲覧（管理者のみ）
│       │   ├── ping.py          # Ping監視の対象 CRUD・WebSocket で結果を配信
│       │   └── schedules.py     # スケジュール CRUD
│       └── services/
│           ├── config_service.py # 対応プラットフォーム（PLATFORMS）・Netmiko での収集・GitPython
│           ├── compliance.py    # コンプライアンスの評価エンジン
│           ├── audit.py         # 操作履歴の記録・ターミナルの記録（asciicast）・保持期間
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
        ├── App.tsx              # ルーティング・ログインガード
        ├── index.css
        ├── auth.tsx             # ログインユーザー・権限（useAuth / RequirePerm）
        ├── platforms.ts         # 対応プラットフォーム一覧の取得（usePlatforms）
        ├── api/client.ts        # Axios クライアント・認証
        ├── topology/            # 構成図（React Flow のノード・接続線・保存形式の変換）
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
            ├── AuditPage.tsx    # 監査ログ（操作履歴・ターミナルの記録の再生）
            ├── PingPage.tsx     # Ping監視（deadman 風）
            └── UsersPage.tsx    # ユーザー管理
```

---

## 今後の拡張ポイント

- **認証強化**: LDAP/AD 連携、MFA、機器グループ単位の権限
- **通知機能**: コンフィグ変更検知・コンプライアンス違反時の Slack / メール通知
- **バックアップ**: config_repo を外部 Git サーバー (GitLab/Gitea) へ push
- **パスワード管理**: HashiCorp Vault 連携
- **踏み台の多段化**: 2段以上の踏み台経由（現在は1段まで）
- **Ping監視の拡張**: 結果の履歴保存・グラフ、応答なしが続いたときの通知、踏み台経由の PING、構成図への死活状態の表示
- **対応プラットフォーム**: 旧 CentreCOM（AlliedWare）・NEC IX・ALAXALA など Netmiko にドライバーの無い機種（独自ドライバーの追加が必要）
- **構成図の自動生成**: LLDP / CDP の隣接情報から接続線を自動作成（現在は手動作成）
