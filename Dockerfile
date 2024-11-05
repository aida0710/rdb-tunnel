FROM rust:1.75-slim-bullseye

# Install build dependencies and libpcap
RUN apt-get update && apt-get install -y \
    pkg-config \
    libpcap-dev \
    build-essential \
    git \
    libpcap0.8 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# 開発環境用の設定
ENV RUST_BACKTRACE=1
ENV RUST_LOG=debug

# コンテナ起動時にcargo runを実行する権限を設定
RUN touch /usr/src/app/placeholder && \
    setcap cap_net_raw,cap_net_admin=eip /usr/local/cargo/bin/cargo
