# 外部への接続で追加で信頼する CA 証明書

アプリ（backend・worker）がインターネットへ HTTPS で接続するとき（Webhook・メールの OAuth 2.0 のトークン・脆弱性情報）に、
OS の既定の信頼に **追加で** 信頼する CA 証明書を置くフォルダーです。HTTPS の中身を検査するプロキシを使う組織で、
その組織の CA（例: Example Corp CA）を置きます。ここに置いたファイルは Git の管理対象外です（この README を除く）。

1. CA 証明書（PEM 形式。`-----BEGIN CERTIFICATE-----` で始まるもの。複数をつなげてもよい）をここに置く
   （例: `/opt/netconfig-manager/certs-outbound/outbound-ca.pem`）。秘密鍵は置かないでください
2. `.env` に `OUTBOUND_CA_FILE=outbound-ca.pem`（ファイルの名前だけ）を書く
3. `bash scripts/setup.sh` でコンテナを作り直す

コンテナの中では `/etc/netconfig/outbound/` に読み取り専用で見えます。ファイルが読めない・PEM でない・証明書が無いときは
backend・worker が起動時にエラーで止まります。期限は画面「システム状態」の「外部への接続」で確認できます。

HTTPS の証明書（nginx のサーバー証明書・秘密鍵）は `certs/` で、このフォルダーとは別です（backend に秘密鍵を見せないため）。
