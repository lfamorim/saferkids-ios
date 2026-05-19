"""
saferkids monitor — multi-tenant
────────────────────────────────
Identifica cada criança pelo IP /32 que o wg-easy atribui ao peer WireGuard
e mantém estado independente por criança. Detecta evasão (VPN/AirPlay
desligados com iPhone ligado) e dispara alertas nominais.

Sinais:

  1. `wg show <iface> dump`               → handshake e allowed_ips de cada peer
  2. `ss` em portas AirPlay (7000/7100)   → qual peer está com sessão ATIVA agora
  3. children.yaml                        → mapa IP → nome amigável
  4. heartbeat HTTPS opcional              → distingue DARK de OFFLINE

Estados por criança:

  RECORDING   handshake recente + sessão AirPlay ativa do IP da criança
  IDLE        handshake recente, mas sem sessão AirPlay         🚨 após IDLE_GRACE
  DARK        handshake antigo, mas heartbeat ou queda <30 min  🚨 imediato
  OFFLINE     handshake antigo, sem heartbeat                   ⚪ silencioso
  UNCLAIMED   peer WG sem entrada em children.yaml              ⚠️  log apenas
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, time as dtime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from aiohttp import ClientSession, ClientTimeout, web

# ── Configuração via ambiente ────────────────────────────────────────────────
WG_INTERFACE     = os.getenv("WG_INTERFACE", "wg0")
RECORDINGS_DIR   = Path(os.getenv("RECORDINGS_DIR", "/recordings"))
CHILDREN_FILE    = Path(os.getenv("CHILDREN_FILE", "/etc/saferkids/children.yaml"))
CHILDREN_URL     = os.getenv("CHILDREN_URL", "")  # ex.: http://saferkids-api:8090/children.json
CHILDREN_FEED_TOKEN = os.getenv("CHILDREN_FEED_TOKEN", "")
POLL_SECONDS     = int(os.getenv("POLL_SECONDS", "30"))
DARK_AFTER       = int(os.getenv("DARK_AFTER_SECONDS", "120"))
OFFLINE_AFTER    = int(os.getenv("OFFLINE_AFTER_SECONDS", "1800"))
HEARTBEAT_FRESH  = int(os.getenv("HEARTBEAT_FRESH_SECONDS", "600"))
HEARTBEAT_TOKEN  = os.getenv("HEARTBEAT_TOKEN", "")
HTTP_PORT        = int(os.getenv("HTTP_PORT", "8080"))
IDLE_GRACE       = int(os.getenv("IDLE_GRACE_SECONDS", "300"))
USAGE_WINDOW     = os.getenv("USAGE_WINDOW", "07:00-22:00")
TZ_NAME          = os.getenv("TZ", "America/Sao_Paulo")
ALERT_COOLDOWN   = int(os.getenv("ALERT_COOLDOWN_SECONDS", "900"))

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT    = os.getenv("TELEGRAM_CHAT_ID", "")
WEBHOOK_URL      = os.getenv("ALERT_WEBHOOK_URL", "")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("saferkids.monitor")


# ── Modelos ─────────────────────────────────────────────────────────────────
@dataclass
class Child:
    ip: str
    name: str
    wg_pubkey: str = ""


@dataclass
class ChildState:
    child: Child
    last_handshake: int = 0
    last_airplay_at: float = 0.0      # última vez que vimos sessão ativa do IP
    last_state: str = "UNKNOWN"
    last_alert_at: float = 0.0
    idle_since: float = 0.0


@dataclass
class GlobalState:
    children_by_ip: dict[str, ChildState] = field(default_factory=dict)
    unclaimed_peers: dict[str, str] = field(default_factory=dict)  # pubkey → ip
    last_heartbeat_at: float = 0.0


STATE = GlobalState()


# ── Registry (children.yaml) ────────────────────────────────────────────────
async def load_children_from_api(session: ClientSession) -> dict[str, Child] | None:
    """Lê crianças via API. Retorna None se a URL não estiver configurada ou falhar."""
    if not CHILDREN_URL:
        return None
    headers = {}
    if CHILDREN_FEED_TOKEN:
        headers["Authorization"] = f"Bearer {CHILDREN_FEED_TOKEN}"
    try:
        async with session.get(CHILDREN_URL, headers=headers,
                               timeout=ClientTimeout(total=10)) as resp:
            if resp.status >= 400:
                log.warning("CHILDREN_URL HTTP %s", resp.status)
                return None
            data = await resp.json()
    except Exception as e:  # noqa: BLE001
        log.warning("falha lendo CHILDREN_URL: %s", e)
        return None
    out: dict[str, Child] = {}
    for d in data:
        try:
            ip = str(d["wg_ip"])
            out[ip] = Child(ip=ip, name=str(d["name"]),
                            wg_pubkey=str(d.get("wg_pubkey", "")))
        except (KeyError, ValueError) as e:
            log.warning("entrada inválida no feed: %s (%s)", d, e)
    return out


def load_children() -> dict[str, Child]:
    """
    Lê children.yaml. Formato:
        "10.8.0.2":
          name: ana
          wg_pubkey: "AAAA...="
    Retorna {} se o arquivo não existir.
    """
    if not CHILDREN_FILE.is_file():
        return {}
    try:
        raw = yaml.safe_load(CHILDREN_FILE.read_text()) or {}
    except yaml.YAMLError as e:
        log.error("children.yaml inválido: %s", e)
        return {}
    out: dict[str, Child] = {}
    for ip, meta in raw.items():
        meta = meta or {}
        out[str(ip)] = Child(
            ip=str(ip),
            name=meta.get("name", str(ip)),
            wg_pubkey=meta.get("wg_pubkey", ""),
        )
    return out


def reconcile_children(registry: dict[str, Child]) -> None:
    """Sincroniza children_by_ip com o registry (preserva estado existente)."""
    for ip, child in registry.items():
        st = STATE.children_by_ip.get(ip)
        if st is None:
            STATE.children_by_ip[ip] = ChildState(child=child)
        else:
            st.child = child  # atualiza nome/pubkey se mudou
    # Remove entradas que sumiram do registry.
    for ip in list(STATE.children_by_ip):
        if ip not in registry:
            log.info("Removendo criança %s (saiu do registry)", ip)
            del STATE.children_by_ip[ip]


# ── Coleta de sinais ────────────────────────────────────────────────────────
_WG_PEER_COLS_MIN = 5

def wg_dump() -> list[tuple[str, str, int]]:
    """Lista (pubkey, allowed_ip /32 sem máscara, last_handshake) por peer."""
    try:
        out = subprocess.check_output(
            ["wg", "show", WG_INTERFACE, "dump"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.warning("wg dump falhou: %s", e)
        return []

    peers = []
    for line in out.strip().splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) < _WG_PEER_COLS_MIN:
            continue
        pubkey = cols[0]
        allowed = cols[3].split(",")[0].strip()  # primeiro CIDR
        ip = allowed.split("/")[0]
        last_hs = int(cols[4]) if cols[4].isdigit() else 0
        peers.append((pubkey, ip, last_hs))
    return peers


def child_dirname(name: str) -> str:
    """Mesma sanitização usada pelo supervisor para nomes de subpasta."""
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")
    return safe or "child"


def latest_mp4_mtime_for(safe_name: str) -> float:
    """Maior mtime entre os MP4s da subpasta da criança (= AirPlay ativo agora)."""
    base = RECORDINGS_DIR / safe_name
    if not base.is_dir():
        return 0.0
    latest = 0.0
    try:
        for mp4 in base.rglob("*.mp4"):
            m = mp4.stat().st_mtime
            if m > latest:
                latest = m
    except FileNotFoundError:
        return 0.0
    return latest


# ── Janela horária ──────────────────────────────────────────────────────────
def in_usage_window() -> bool:
    try:
        start_s, end_s = USAGE_WINDOW.split("-")
        start = dtime.fromisoformat(start_s.strip())
        end   = dtime.fromisoformat(end_s.strip())
    except Exception:  # noqa: BLE001
        return True
    now = datetime.now(ZoneInfo(TZ_NAME)).time()
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end


# ── State machine ──────────────────────────────────────────────────────────
def classify(st: ChildState, now: float) -> str:
    age = now - st.last_handshake if st.last_handshake else float("inf")
    airplay_active = (now - st.last_airplay_at) < DARK_AFTER  # gerar tráfego AirPlay = vivo
    heartbeat_fresh = (now - STATE.last_heartbeat_at) < HEARTBEAT_FRESH

    if age < DARK_AFTER:
        return "RECORDING" if airplay_active else "IDLE"
    if age < OFFLINE_AFTER or heartbeat_fresh:
        return "DARK"
    return "OFFLINE"


# ── Alertas ────────────────────────────────────────────────────────────────
def _fmt_age(epoch: int | float) -> str:
    if not epoch:
        return "nunca"
    age = int(time.time() - epoch)
    if age < 60:   return f"{age}s atrás"
    if age < 3600: return f"{age // 60}min atrás"
    return f"{age // 3600}h atrás"


async def send_alert(session: ClientSession, st: ChildState, new_state: str, reason: str):
    msg = (
        f"🚨 *saferkids-ios* — alerta\n"
        f"Criança: *{st.child.name}* (`{st.child.ip}`)\n"
        f"Estado: *{st.last_state} → {new_state}*\n"
        f"Motivo: {reason}\n"
        f"Última handshake WG: {_fmt_age(st.last_handshake)}\n"
        f"Última sessão AirPlay: {_fmt_age(st.last_airplay_at)}\n"
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
            "event": "saferkids.alert",
            "child": st.child.name,
            "ip": st.child.ip,
            "previous_state": st.last_state,
            "new_state": new_state,
            "reason": reason,
            "timestamp": int(time.time()),
        }, timeout=10))

    if not tasks:
        log.warning("Nenhum canal de alerta configurado.")
        return

    for coro in tasks:
        try:
            async with await coro as resp:
                if resp.status >= 400:
                    log.error("Alert falhou: HTTP %s", resp.status)
        except Exception as e:  # noqa: BLE001
            log.error("Alert exception: %s", e)


# ── Loop principal ─────────────────────────────────────────────────────────
async def poll_loop(session: ClientSession):
    while True:
        try:
            now = time.time()
            via_api = await load_children_from_api(session)
            reconcile_children(via_api if via_api is not None else load_children())

            wg_peers = wg_dump()

            # Atualiza estado por criança a partir dos peers do WG.
            seen_ips = set()
            for pubkey, ip, last_hs in wg_peers:
                seen_ips.add(ip)
                st = STATE.children_by_ip.get(ip)
                if st is None:
                    # Peer existe no WG mas não tem entrada no registry.
                    if STATE.unclaimed_peers.get(pubkey) != ip:
                        log.warning("peer não-registrado: ip=%s pubkey=%s",
                                    ip, pubkey[:12])
                        STATE.unclaimed_peers[pubkey] = ip
                    continue
                st.last_handshake = max(st.last_handshake, last_hs)

            # AirPlay ativo = MP4 da criança recém-escrito (supervisor grava
            # em RECORDINGS_DIR/<safe_name>/ enquanto a sessão acontece).
            for st in STATE.children_by_ip.values():
                m = latest_mp4_mtime_for(child_dirname(st.child.name))
                if m > st.last_airplay_at:
                    st.last_airplay_at = m

            # Avalia state machine para cada criança configurada.
            for st in STATE.children_by_ip.values():
                new_state = classify(st, now)
                if new_state != st.last_state:
                    log.info("%s (%s): %s → %s",
                             st.child.name, st.child.ip, st.last_state, new_state)

                if new_state == "IDLE":
                    if st.last_state != "IDLE":
                        st.idle_since = now
                else:
                    st.idle_since = 0.0

                window_ok = in_usage_window()
                cooled = (now - st.last_alert_at) >= ALERT_COOLDOWN
                reason: str | None = None

                if new_state == "DARK" and window_ok and (st.last_state != "DARK" or cooled):
                    reason = (
                        "WG sem handshake mas heartbeat externo recente — "
                        "VPN provavelmente desligada manualmente"
                        if (now - STATE.last_heartbeat_at) < HEARTBEAT_FRESH
                        else "WG caiu repentinamente — possível desligar manual da VPN"
                    )
                elif (new_state == "IDLE"
                      and window_ok
                      and (now - st.idle_since) >= IDLE_GRACE
                      and cooled):
                    minutes = int((now - st.idle_since) // 60)
                    reason = (
                        f"VPN ligada há {minutes}min sem espelhamento ativo — "
                        "AirPlay pode ter sido desligado (criança usando o iPhone sem mirroring)"
                    )

                if reason:
                    st.last_alert_at = now
                    await send_alert(session, st, new_state, reason)

                st.last_state = new_state

        except Exception as e:  # noqa: BLE001
            log.exception("poll error: %s", e)

        await asyncio.sleep(POLL_SECONDS)


# ── HTTP ───────────────────────────────────────────────────────────────────
async def handle_heartbeat(req: web.Request) -> web.Response:
    if not HEARTBEAT_TOKEN:
        return web.Response(status=503, text="heartbeat desabilitado")
    token = req.query.get("token") or req.headers.get("X-Heartbeat-Token", "")
    if not secrets.compare_digest(token, HEARTBEAT_TOKEN):
        return web.Response(status=403, text="forbidden")
    STATE.last_heartbeat_at = time.time()
    return web.json_response({"ok": True, "ts": int(STATE.last_heartbeat_at)})


async def handle_status(_req: web.Request) -> web.Response:
    now = time.time()
    return web.json_response({
        "children": [
            {
                "name": st.child.name,
                "ip": st.child.ip,
                "wg_pubkey": st.child.wg_pubkey,
                "state": st.last_state,
                "wg_handshake_age_s": int(now - st.last_handshake) if st.last_handshake else None,
                "airplay_age_s":      int(now - st.last_airplay_at) if st.last_airplay_at else None,
                "idle_for_s":         int(now - st.idle_since) if st.idle_since else 0,
            }
            for st in STATE.children_by_ip.values()
        ],
        "unclaimed_peers": [
            {"pubkey": pk, "ip": ip} for pk, ip in STATE.unclaimed_peers.items()
        ],
        "heartbeat_age_s": int(now - STATE.last_heartbeat_at) if STATE.last_heartbeat_at else None,
        "in_usage_window": in_usage_window(),
    })


_STATE_NUM = {"UNKNOWN": 0, "RECORDING": 1, "IDLE": 2, "DARK": 3, "OFFLINE": 4}

async def handle_metrics(_req: web.Request) -> web.Response:
    now = time.time()
    lines = ["# HELP saferkids_child_state 0=UNKNOWN 1=RECORDING 2=IDLE 3=DARK 4=OFFLINE"]
    for st in STATE.children_by_ip.values():
        label = f'child="{st.child.name}",ip="{st.child.ip}"'
        lines.append(f"saferkids_child_state{{{label}}} {_STATE_NUM.get(st.last_state, 0)}")
        if st.last_handshake:
            lines.append(f"saferkids_child_wg_handshake_age_seconds{{{label}}} {int(now - st.last_handshake)}")
        if st.last_airplay_at:
            lines.append(f"saferkids_child_airplay_age_seconds{{{label}}} {int(now - st.last_airplay_at)}")
    lines.append(f"saferkids_unclaimed_peers {len(STATE.unclaimed_peers)}")
    lines.append(f"saferkids_heartbeat_age_seconds {int(now - STATE.last_heartbeat_at) if STATE.last_heartbeat_at else -1}")
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
    log.info("HTTP em :%d (heartbeat, status, metrics) | children=%s",
             HTTP_PORT, str(CHILDREN_FILE))

    async with ClientSession() as session:
        await poll_loop(session)


if __name__ == "__main__":
    asyncio.run(main())
