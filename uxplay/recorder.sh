#!/usr/bin/env bash
# Reads UXPlay's raw H.264 stream from $FIFO and segments it into rolling
# MP4 files of $SEGMENT_SECONDS each, named with the session start timestamp.
#
# Each AirPlay session = one open/close of the FIFO. When the iPhone stops
# mirroring, ffmpeg sees EOF and exits; we just loop and wait for the next
# session.
set -euo pipefail

: "${SEGMENT_SECONDS:=600}"
: "${RECORDINGS_DIR:=/recordings}"
: "${FIFO:=/tmp/uxplay-video.fifo}"
: "${INPUT_FRAMERATE:=60}"   # iOS mirrors at up to 60 fps; safe upper bound.

mkdir -p "$RECORDINGS_DIR"

while true; do
    # Open() on the FIFO blocks until UXPlay opens the write side, i.e. until
    # an AirPlay session actually starts -- so this loop is idle until then.
    SESSION_TS="$(date +%Y%m%d_%H%M%S)"
    SESSION_DIR="$RECORDINGS_DIR/$SESSION_TS"
    mkdir -p "$SESSION_DIR"

    OUT_PATTERN="$SESSION_DIR/${SESSION_TS}_part_%03d.mp4"
    echo "[recorder] waiting for next AirPlay session → $OUT_PATTERN"

    # -f h264          : input is a raw H.264 elementary stream
    # -framerate       : raw H.264 has no timing; declare iOS mirroring fps
    # -c:v copy        : no re-encode, ~free CPU and lossless
    # -f segment       : split into fixed-length files
    # -reset_timestamps: each segment starts at 0, so each MP4 plays standalone
    # -movflags +faststart : web-friendly MP4 atoms
    ffmpeg -hide_banner -loglevel warning \
        -fflags +genpts \
        -f h264 -framerate "$INPUT_FRAMERATE" \
        -i "$FIFO" \
        -c:v copy \
        -f segment \
        -segment_time "$SEGMENT_SECONDS" \
        -segment_format mp4 \
        -segment_format_options "movflags=+faststart" \
        -reset_timestamps 1 \
        -strftime 0 \
        "$OUT_PATTERN" || true

    echo "[recorder] session ended; segments saved in $SESSION_DIR"

    # If the session produced no frames at all, drop the empty dir so the
    # recordings folder stays tidy.
    rmdir --ignore-fail-on-non-empty "$SESSION_DIR" 2>/dev/null || true

    # Tiny pause so we don't spin if the FIFO is closed faster than we loop.
    sleep 1
done
