FROM rust:1.90-bookworm AS bridge
WORKDIR /build
COPY milter/Cargo.toml milter/Cargo.lock ./
COPY milter/src ./src
RUN cargo build --locked

FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    cmake ninja-build g++ pkg-config ragel libglib2.0-dev libssl-dev libsodium-dev \
    libpcre2-dev libicu-dev libsqlite3-dev libarchive-dev libluajit-5.1-dev \
    zlib1g-dev libzstd-dev redis-server postfix python3 python3-dkim ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY rspamd /src
RUN cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX=/opt/rspamd -DENABLE_HYPERSCAN=OFF -DENABLE_BLAS=OFF \
    -DENABLE_LIBUNWIND=OFF -DENABLE_JEMALLOC=OFF \
    && ninja -C /build -j2 install
COPY --from=bridge /build/target/debug/mta-hooks-milter /usr/local/bin/mta-hooks-milter
ENTRYPOINT ["python3", "-u", "/src/test/functional/util/mta_hooks_test.py", "--rspamd", "/opt/rspamd/bin/rspamd", "--milter", "/usr/local/bin/mta-hooks-milter", "--postfix"]
