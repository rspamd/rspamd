# Context: a clean Rspamd checkout in source/, this directory in fixture/.
# Run the resulting image with --network none; no host mounts are required.
FROM debian:bookworm-slim AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build ragel pkg-config perl ca-certificates \
    libglib2.0-dev libluajit-5.1-dev libpcre2-dev libssl-dev libsqlite3-dev \
    libicu-dev libsodium-dev libarchive-dev zlib1g-dev postfix python3 \
    && rm -rf /var/lib/apt/lists/*
COPY source/ /source/
RUN cmake -S /source -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/rspamd -DENABLE_HYPERSCAN=OFF -DENABLE_BACKWARD=OFF \
    -DINSTALL_WEBUI=OFF -DWANT_SYSTEMD_UNITS=OFF \
    && cmake --build /build --parallel 2 --target install

FROM build AS test
COPY fixture/ /opt/postfix-data/
ENTRYPOINT ["python3", "-u", "/opt/postfix-data/test.py"]
