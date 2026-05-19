"""
saferkids monitor
─────────────────
Detecta evasão da supervisão: iPhone ligado, mas WireGuard / AirPlay
desligados. Combina três fontes de sinal:

  1. `wg show wg0 dump`              → última handshake de cada peer
  2. presença de um arquivo MP4 sendo escrito em $RECORDINGS_DIR  → AirPlay ativo
  3. heartbeat HTTPS de um Atalho iOS (`/heartbeat?token=...`)    → telefone está
     online por fora da VPN

Estados por peer:

  RECORDING   wg recente + AirPlay ativo
  IDLE        wg recente + AirPlay inativo
  DARK        wg parou + (heartbeat recente OU primeira queda há pouco)
              → ALERTA: provável desligar manual da VPN
  OFFLINE     wg parou há muito + sem heartbeat → telefone provavelmente desligado

Toda transição para DARK dispara alerta para os pais via:
  - Telegram bot   (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)
  - Webhook genérico (ALERT_WEBHOOK_URL — JSON POST)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from datetime import datetime, time as dtime
from zoneinfo import ZoneInfo

from aiohttp import ClientSession, web

# ── Configuração via ambiente ────────────────────────────────────────────────
WG_INTERFACE     = os.getenv("WG_INTERFACE", "wg0")
RECORDINGS_DIR   = Path(os.getenv("RECORDINGS_DIR", "/recordings"))
POLL_SECONDS     = int(os.getenv("POLL_SECONDS", "30"))
DARK_AFTER       = int(os.getenv("DARK_AFTER_SECONDS", "120"))    # 2 min sem handshake → DARK
OFFLINE_AFTER    = int(os.getenv("OFFLINE_AFTER_SECONDS", "1800")) # 30 min → OFFLINE
AIRPLAY_FRESH    = int(os.getenv("AIRPLAY_FRESH_SECONDS", "60"))
HEARTBEAT_FRESH  = int(os.getenv("HEARTBEAT_FRESH_SECONDS", "600"))  # heartbeat válido por 10 min
HEARTBEAT_TOKEN  = os.getenv("HEARTBEAT_TOKEN", "")  # token compartilhado com o Shortcut
HTTP_PORT        = int(os.getenv("HTTP_PORT", "8080"))

# IDLE prolongado = "VPN ligada (criança com o celular na mão) mas AirPlay
# desligado". Alertamos só depois de IDLE_GRACE para não disparar quando o
# telefone estiver brevemente bloqueado entre sessões.
IDLE_GRACE       = int(os.getenv("IDLE_GRACE_SECONDS", "300"))      # 5 min
# Janela de uso esperado (hora local 24h). Fora dela ficamos em "modo silencioso"
# — útil para não alertar de madrugada quando o aparelho fica legitimamente off.
USAGE_WINDOW     = os.getenv("USAGE_WINDOW", "07:00-22:00")
TZ_NAME          = os.getenv("TZ", "America/Sao_Paulo")

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT    = os.getenv("TELEGRAM_CHAT_ID", "")
WEBHOOK_URL      = os.getenv("ALERT_WEBHOOK_URL", "")
ALERT_COOLDOWN   = int(os.getenv("ALERT_COOLDOWN_SECONDS", "900"))  # 15 min entre alertas iguais

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("saferkids.monitor")


# ── Estado por peer ──────────────────────────────────────────────────────────
@dataclass
class PeerState:
    public_key: str
    name: str = ""
    last_handshake: int = 0      # epoch seconds, 0 = nunca
    last_state: str = "UNKNOWN"
    last_alert_at: float = 0.0
    idle_since: float = 0.0      # quando entrou em IDLE pela última vez


@dataclass
class GlobalState:
    peers: dict[str, PeerState] = field(default_factory=dict)
    last_heartbeat_at: float = 0.0
    last_airplay_at: float = 0.0  # mtime do arquivo .mp4 mais recente


STATE = GlobalState()


# ── Coleta de sinais ─────────────────────────────────────────────────────────
def wg_dump() -> list[PeerState]:
    """Lê `wg show <iface> dump` e devolve a lista de peers."""
    try:
        out = subprocess.check_output(
            ["wg", "show", WG_INTERFACE, "dump"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.warning("wg dump falhou: %s", e)
        return []

    peers: list[PeerState] = []
    # Primeira linha = interface, demais = peers.
    # Colunas (peer): public_key  preshared_key  endpoint  allowed_ips  latest_handshake  rx  tx  keepalive
    for line in out.strip().splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        peers.append(PeerState(
            public_key=cols[0],
            last_handshake=int(cols[4]) if cols[4].isdigit() else 0,
        ))
    return peers


def latest_mp4_mtime() -> float:
    """Maior mtime entre todos os MP4s — proxy de "AirPlay recebendo agora"."""
    try:
        latest = 0.0
        for mp4 in RECORDINGS_DIR.rglob("*.mp4"):
            m = mp4.stat().st_mtime
            if m > latest:
                latest = m
        return latest
    except FileNotFoundError:
        return 0.0


# ── State machine ────────────────────────────────────────────────────────────
def classify(peer: PeerState, now: float) -> str:
    age = now - peer.last_handshake if peer.last_handshake else float("inf")
    airplay_active = (now - STATE.last_airplay_at) < AIRPLAY_FRESH
    heartbeat_fresh = (now - STATE.last_heartbeat_at) < HEARTBEAT_FRESH

    if age < DARK_AFTER:
        return "RECORDING" if airplay_active else "IDLE"

    # WG parou de bater handshake.
    if age < OFFLINE_AFTER or heartbeat_fresh:
        # Pouco tempo desde a última handshake OU heartbeat externo confirmando
        # que o iPhone está online → é evasão da VPN.
        return "DARK"

    return "OFFLINE"


# ── Alertas ──────────────────────────────────────────────────────────────────
async def send_alert(session: ClientSession, peer: PeerState, new_state: str, reason: str):
    msg = (
        f"🚨 *saferkids-ios* — possível evasão detectada\n"
        f"Peer: `{peer.name or peer.public_key[:12]}`\n"
        f"Estado: *{peer.last_state} → {new_state}*\n"
        f"Motivo: {reason}\n"
        f"Última handshake WG: {_fmt_age(peer.last_handshake)}\n"
        f"Heartbeat externo: {_fmt_age(int(STATE.last_heartbeat_at))}\n"
    )
    log.warning(msg.replace("\n", " | "))

    tasks = []
    if TELEGRAM_TOKEN and TELEGRAM_CHAT:
        tasks.append(session.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT, "text": msg, "parse_mode": "Markdown"},
            timeout=10,
        ))
    if WEBHOOK_URL:
        tasks.append(session.post(WEBHOOK_URL, json={
            "event": "saferkids.evasion",
            "peer": peer.name or peer.public_key,
            "previous_state": peer.last_state,
            "new_state": new_state,
            "reason": reason,
            "timestamp": int(time.time()),
        }, timeout=10))

    if not tasks:
        log.warning("Nenhum canal de alerta configurado (TELEGRAM_* ou ALERT_WEBHOOK_URL).")
        return

    for coro in tasks:
        try:
            async with await coro as resp:
                if resp.status >= 400:
                    log.error("Alert failed: HTTP %s", resp.status)
        except Exception as e:  # noqa: BLE001
            log.error("Alert exception: %s", e)


def in_usage_window() -> bool:
    """True se 'agora' (hora local TZ_NAME) cai na janela USAGE_WINDOW."""
    try:
        start_s, end_s = USAGE_WINDOW.split("-")
        start = dtime.fromisoformat(start_s.strip())
        end   = dtime.fromisoformat(end_s.strip())
    except Exception:  # noqa: BLE001
        return True  # config inválida → não silencia
    now = datetime.now(ZoneInfo(TZ_NAME)).time()
    if start <= end:
        return start <= now <= end
    # Janela atravessa meia-noite (ex.: 22:00-06:00).
    return now >= start or now <= end


def _fmt_age(epoch: int) -> str:
    if not epoch:
        return "nunca"
    age = int(time.time()) - epoch
    if age < 60:   return f"{age}s atrás"
    if age < 3600: return f"{age // 60}min atrás"
    return f"{age // 3600}h atrás"


# ── Loop principal ───────────────────────────────────────────────────────────
async def poll_loop(session: ClientSession):
    while True:
        try:
            now = time.time()
            STATE.last_airplay_at = latest_mp4_mtime()

            for fresh in wg_dump():
                prev = STATE.peers.get(fresh.public_key)
                if prev:
                    prev.last_handshake = fresh.last_handshake
                    peer = prev
                else:
                    peer = fresh
                    STATE.peers[peer.public_key] = peer

                new_state = classify(peer, now)
                if new_state != peer.last_state:
                    log.info("peer %s: %s → %s",
                             peer.name or peer.public_key[:12], peer.last_state, new_state)

                # Marca quando entrou em IDLE pra medir IDLE_GRACE.
                if new_state == "IDLE":
                    if peer.last_state != "IDLE":
                        peer.idle_since = now
                else:
                    peer.idle_since = 0.0

                window_ok = in_usage_window()
                cooled = (now - peer.last_alert_at) >= ALERT_COOLDOWN
                reason = None

                if new_state == "DARK" and window_ok and (peer.last_state != "DARK" or cooled):
                    reason = (
                        "WG sem handshake mas heartbeat do Atalho iOS continua chegando — "
                        "VPN provavelmente desligada manualmente"
                        if (now - STATE.last_heartbeat_at) < HEARTBEAT_FRESH
                        else "WG caiu repentinamente — possível desligar manual da VPN"
                    )
                elif (new_state == "IDLE"
                      and window_ok
                      and (now - peer.idle_since) >= IDLE_GRACE
                      and cooled):
                    reason = (
                        f"VPN ligada (criança com o iPhone na mão) há "
                        f"{int((now - peer.idle_since) // 60)}min sem espelhamento ativo — "
                        "AirPlay pode ter sido desligado"
                    )

                if reason:
                    peer.last_alert_at = now
                    await send_alert(session, peer, new_state, reason)

                peer.last_state = new_state
        except Exception as e:  # noqa: BLE001
            log.exception("poll error: %s", e)

        await asyncio.sleep(POLL_SECONDS)


# ── HTTP: heartbeat do Atalho iOS + métricas + status ───────────────────────
async def handle_heartbeat(req: web.Request) -> web.Response:
    if not HEARTBEAT_TOKEN:
        return web.Response(status=503, text="heartbeat desabilitado")
    token = req.query.get("token") or req.headers.get("X-Heartbeat-Token", "")
    if not secrets.compare_digest(token, HEARTBEAT_TOKEN):
        return web.Response(status=403, text="forbidden")
    STATE.last_heartbeat_at = time.time()
    log.debug("heartbeat recebido")
    return web.json_response({"ok": True, "ts": int(STATE.last_heartbeat_at)})


async def handle_status(_req: web.Request) -> web.Response:
    now = time.time()
    return web.json_response({
        "peers": [
            {
                "public_key": p.public_key,
                "name": p.name,
                "state": p.last_state,
                "last_handshake_age_s": int(now - p.last_handshake) if p.last_handshake else None,
            }
            for p in STATE.peers.values()
        ],
        "heartbeat_age_s": int(now - STATE.last_heartbeat_at) if STATE.last_heartbeat_at else None,
        "airplay_age_s":  int(now - STATE.last_airplay_at)  if STATE.last_airplay_at  else None,
    })


async def handle_metrics(_req: web.Request) -> web.Response:
    """Formato Prometheus mínimo."""
    now = time.time()
    lines = ["# HELP saferkids_peer_state 0=UNKNOWN 1=RECORDING 2=IDLE 3=DARK 4=OFFLINE"]
    mapping = {"UNKNOWN": 0, "RECORDING": 1, "IDLE": 2, "DARK": 3, "OFFLINE": 4}
    for p in STATE.peers.values():
        lines.append(
            f'saferkids_peer_state{{peer="{p.name or p.public_key[:12]}"}} '
            f'{mapping.get(p.last_state, 0)}'
        )
    lines.append(f"saferkids_heartbeat_age_seconds {int(now - STATE.last_heartbeat_at) if STATE.last_heartbeat_at else -1}")
    lines.append(f"saferkids_airplay_age_seconds {int(now - STATE.last_airplay_at) if STATE.last_airplay_at else -1}")
    return web.Response(text="\n".join(lines) + "\n", content_type="text/plain")


async def main():
    app = web.Application()
    app.router.add_get("/heartbeat", handle_heartbeat)
    app.router.add_get("/status", handle_status)
    app.router.add_get("/metrics", handle_metrics)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    log.info("HTTP server escutando em :%d (heartbeat, status, metrics)", HTTP_PORT)

    async with ClientSession() as session:
        await poll_loop(session)


if __name__ == "__main__":
    asyncio.run(main())
