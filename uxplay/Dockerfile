# Builds UXPlay from source with the GStreamer plugins needed for headless
# recording, plus Avahi (so the iPhone can discover the receiver via Bonjour
# over the WireGuard interface) and ffmpeg (for MP4 segmentation).
FROM debian:bookworm-slim AS build

ARG UXPLAY_VERSION=1.68

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates cmake build-essential pkg-config \
        libssl-dev libplist-dev \
        libavahi-compat-libdnssd-dev \
        libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch ${UXPLAY_VERSION} https://github.com/FDH2/UxPlay.git \
    && cd UxPlay && cmake . && make -j"$(nproc)" \
    && install -Dm755 uxplay /out/usr/local/bin/uxplay

# ─── runtime image ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 libplist3 \
        avahi-daemon avahi-utils libnss-mdns dbus \
        libavahi-compat-libdnssd1 \
        gstreamer1.0-plugins-base \
        gstreamer1.0-plugins-good \
        gstreamer1.0-plugins-bad \
        gstreamer1.0-plugins-ugly \
        gstreamer1.0-libav \
        gstreamer1.0-tools \
        ffmpeg \
        iproute2 \
        python3 python3-yaml \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /
COPY supervisor.py /supervisor.py
COPY avahi-daemon.conf /etc/avahi/avahi-daemon.conf

VOLUME ["/recordings"]

ENTRYPOINT ["/usr/bin/tini", "--", "python3", "-u", "/supervisor.py"]
