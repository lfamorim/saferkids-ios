#!/usr/bin/env bash
# Starts D-Bus + Avahi (for Bonjour discovery on every iface, including wg0),
# then launches UXPlay with its H.264 stream piped into a FIFO, while a
# background ffmpeg loop segments that stream into rolling MP4 files.
set -euo pipefail

: "${UXPLAY_NAME:=iPhone-Recorder}"
: "${SEGMENT_SECONDS:=600}"
: "${RECORDINGS_DIR:=/recordings}"

mkdir -p "$RECORDINGS_DIR"
chmod 0777 "$RECORDINGS_DIR" || true

# ── D-Bus + Avahi ────────────────────────────────────────────────────────────
mkdir -p /var/run/dbus
rm -f /var/run/dbus/pid
dbus-daemon --system --fork >/dev/null 2>&1 || true

# Avahi refuses to run as root by default; create the user if missing.
id -u avahi >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin avahi
mkdir -p /var/run/avahi-daemon
chown -R avahi:avahi /var/run/avahi-daemon
avahi-daemon --daemonize --no-drop-root=no >/dev/null 2>&1 || \
    avahi-daemon --daemonize >/dev/null 2>&1 || true

# Wait briefly for Avahi to be ready.
for _ in 1 2 3 4 5; do
    if avahi-browse -at >/dev/null 2>&1; then break; fi
    sleep 1
done

# ── FIFO that UXPlay writes the encoded H.264 stream to ──────────────────────
FIFO=/tmp/uxplay-video.fifo
rm -f "$FIFO"
mkfifo "$FIFO"

# ── Background segmenter ─────────────────────────────────────────────────────
SEGMENT_SECONDS="$SEGMENT_SECONDS" RECORDINGS_DIR="$RECORDINGS_DIR" \
    FIFO="$FIFO" /recorder.sh &

RECORDER_PID=$!

cleanup() {
    echo "[entrypoint] shutting down…"
    kill "$RECORDER_PID" 2>/dev/null || true
    rm -f "$FIFO"
}
trap cleanup EXIT INT TERM

echo "[entrypoint] starting UXPlay as '$UXPLAY_NAME'"
# -n      : friendly AirPlay name
# -nh     : don't append the host's name
# -vs 0   : no video display window (headless)
# -as 0   : no audio playback (we only need to record video)
# -vdmp   : tap the decrypted H.264 stream into our FIFO
exec uxplay \
    -n "$UXPLAY_NAME" \
    -nh \
    -vs 0 \
    -as 0 \
    -vdmp "$FIFO"
