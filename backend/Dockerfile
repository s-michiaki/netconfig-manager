FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 追加で信頼する CA（HTTPS の中身を検査するプロキシの組織の CA）。scripts/setup.sh がビルドの直前に、.env の
# OUTBOUND_CA_FILE を build-ca/outbound-ca.crt へ写す。無ければ build-ca/ は README.md だけで、ここでは何も増えない。
# OS の信頼ストアに入れるので、後の apt-get・pip と、実行時のアプリが使う（CA の証明書は秘密ではない）。
# プロキシの URL・認証情報は ARG / ENV に書かない（podman build が RUN にだけ渡し、イメージには残さない）
COPY build-ca/ /usr/local/share/ca-certificates/netconfig-build/
RUN cd /usr/local/share/ca-certificates/netconfig-build && rm -f README.md \
 && if ls ./*.crt >/dev/null 2>&1; then update-ca-certificates; else cd / && rmdir /usr/local/share/ca-certificates/netconfig-build; fi

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt はロックファイル（全部の版とハッシュを固定。requirements.in から scripts/lock_deps.sh で生成）。
# --require-hashes で、ロックに無いパッケージや中身の違うファイルは入れない（再ビルドで版が変わらないようにする）
COPY requirements.txt .
# 追加の CA があるときは、pip にも OS の信頼ストア（追加の CA を含む）を明示する（pip の版によっては certifi だけを見るため）
RUN if [ -d /usr/local/share/ca-certificates/netconfig-build ]; then export PIP_CERT=/etc/ssl/certs/ca-certificates.crt; fi \
 && pip install --no-cache-dir --require-hashes -r requirements.txt

COPY . .

# コンフィグ世代管理用リポジトリ・SSH known_hosts・ターミナルの記録の置き場所（ボリュームをマウントする）
# （build-ca/ は COPY . . で /app にも入るので消す。CA は上で OS の信頼ストアに入れてある）
RUN rm -rf /app/build-ca && mkdir -p /app/configs /data/ssh /data/terminal-logs

# OS のパッケージのセキュリティ修正を取り込む（土台のイメージが作り直されるのを待たずに）。
# setup.sh が OS_UPGRADE に日付を渡すので、ビルドのキャッシュがあっても日に 1 回はやり直す（#18）
ARG OS_UPGRADE=
RUN echo "OS_UPGRADE=${OS_UPGRADE}" && apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
