# Content-Security-Policy（CSP）の値。http.conf・https.conf の http コンテキストから include し、
# common.inc の add_header で付ける。画面テスト（e2e の csp プロジェクト）もこのファイルの値を読んで同じ CSP で確認する
#
# 画面（既定）: スクリプト・接続・画像・フォントは同じサーバーのものだけにする（Web フォントもビルドに含めている）。例外は次の 2 つだけ
#   style-src 'unsafe-inline' … ターミナル（xterm.js）が <style> 要素を JS で作って色や文字の大きさを設定するため、
#                               構成図の印刷用ウィンドウ（開いた画面の CSP を引き継ぐ）が <style> を書き込むため
#   img-src data:             … 構成図の PNG / PDF 書き出し・印刷が、図を data: URL の画像にして描くため
#   スクリプトの 'unsafe-inline' / 'unsafe-eval' は付けない（XSS 対策の本体。トークンを localStorage に置いているため）
#   WebSocket（ターミナル・Ping 監視）は同じホストへの ws: / wss: なので connect-src 'self' で通る
#   CSV・コンフィグ・PNG などのダウンロード（blob: の URL を <a download> で開く）は CSP の対象外
# /docs（Swagger UI。backend の FastAPI が返す）だけは、CDN（cdn.jsdelivr.net）のスクリプト・CSS と
#   HTML 内のスクリプトを使うため緩める（画面と同じ CSP では真っ白になる）。/openapi.json は JSON なので画面と同じでよい
# location ごとに add_header を書くと server の add_header（HSTS など）が継承されなくなるため、map で値だけを切り替える
map $uri $ncm_csp {
    default "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    /docs   "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
}
