FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt はロックファイル（全部の版とハッシュを固定。requirements.in から scripts/lock_deps.sh で生成）。
# --require-hashes で、ロックに無いパッケージや中身の違うファイルは入れない（再ビルドで版が変わらないようにする）
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY . .

# コンフィグ世代管理用リポジトリ・SSH known_hosts・ターミナルの記録の置き場所（ボリュームをマウントする）
RUN mkdir -p /app/configs /data/ssh /data/terminal-logs

# OS のパッケージのセキュリティ修正を取り込む（土台のイメージが作り直されるのを待たずに）。
# setup.sh が OS_UPGRADE に日付を渡すので、ビルドのキャッシュがあっても日に 1 回はやり直す（#18）
ARG OS_UPGRADE=
RUN echo "OS_UPGRADE=${OS_UPGRADE}" && apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
