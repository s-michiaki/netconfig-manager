FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Gitのグローバル設定
RUN git config --global user.email "netconfig@system.local" \
    && git config --global user.name "NetConfig System"

EXPOSE 8000
