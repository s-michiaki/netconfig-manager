# HTTPS の証明書

本番構成（docker-compose.prod.yml）の nginx が読み込む証明書を置くフォルダーです。
ここに置いたファイルは Git の管理対象外です（この README を除く）。

| ファイル | 内容 |
|---|---|
| `server.crt` | サーバー証明書（中間 CA を含むチェーン） |
| `server.key` | 秘密鍵（暗号化されていないもの） |
| `ca.crt` | ルート CA 証明書（任意。`/ca.crt` で利用者がダウンロードできる） |

手で置かずに、次のスクリプトで配置してください（内容のチェック・権限設定・nginx の再起動まで行います）。

```bash
bash scripts/import_cert.sh
```

`server.crt` と `server.key` が無ければ HTTP だけで起動します。
