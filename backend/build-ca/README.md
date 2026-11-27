# ビルド用の追加の CA（setup.sh が置く）

コンテナのビルドの中（apt-get・pip・npm・apk）で、HTTPS の中身を検査するプロキシの組織の CA を信頼させるための置き場所です。
`scripts/setup.sh` がビルドの直前に、`.env` の `OUTBOUND_CA_FILE`（`certs-outbound/` の中のファイル）を
`outbound-ca.crt` の名前でここへ写し、CA を使わない設定に戻したときは消します。手で置く必要はありません。

- ここに置いたファイルは Git の管理対象外です（この README を除く）。
- この README だけのときは、Dockerfile は何も追加しません（CA なしのビルドと同じ結果）。
- プロキシの URL・認証情報はここにも Dockerfile にも書きません（podman build がビルドの中の RUN にだけ渡し、イメージには残りません）。
