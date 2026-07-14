FROM rust:1.75-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml backend/Cargo.toml
COPY apps/cli/Cargo.toml apps/cli/Cargo.toml
COPY apps/dashboard/package.json apps/dashboard/package-lock.json apps/dashboard/

RUN mkdir -p backend/src && echo 'fn main() {}' > backend/src/main.rs \
    && mkdir -p apps/cli/src && echo 'fn main() {}' > apps/cli/src/main.rs \
    && cargo build --release || true \
    && rm -rf backend/src apps/cli/src

COPY . .

RUN touch backend/src/main.rs apps/cli/src/main.rs \
    && cargo build --release --locked

WORKDIR /app/apps/dashboard
RUN npm ci && npm run build

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinelx && useradd -r -g sentinelx -d /var/lib/sentinelx -s /sbin/nologin sentinelx \
    && mkdir -p /var/lib/sentinelx /etc/sentinelx \
    && chown sentinelx:sentinelx /var/lib/sentinelx /etc/sentinelx

COPY --from=builder /app/target/release/sentinelx-backend /usr/bin/sentinelx-backend
COPY --from=builder /app/target/release/sentinelx-cli /usr/bin/sentinelx-cli
COPY --from=builder /app/apps/dashboard/dist /usr/share/sentinelx/dashboard
COPY packaging/sentinelx.conf /etc/sentinelx/sentinelx.conf

EXPOSE 8443

VOLUME /var/lib/sentinelx

ENV RUST_LOG=info
ENV SENTINELX_CONFIG=/etc/sentinelx/sentinelx.toml

ENTRYPOINT ["/usr/bin/sentinelx-backend"]
