"""
saferkids supervisor — N AirPlay simultâneos por Pod
─────────────────────────────────────────────────────
Para cada criança designada a este Pod, mantém um processo `uxplay` dedicado
(nome Bonjour `<UXPLAY_PREFIX>-<child>`) e um processo `ffmpeg` que segmenta
o stream H.264 em arquivos MP4 sob `<RECORDINGS_DIR>/<child>/`.

Sharding por ordinal (escala horizontal):
    POD_NAME=saferkids-2  →  ordinal=2
    REPLICAS=4
    → atende crianças com (child.id % 4) == 2
Quando POD_NAME ou REPLICAS não estão setados, atende todas.

Reconciliação a cada RECONCILE_SECONDS:
  - Adiciona crianças novas (spawn UXPlay+ffmpeg).
  - Remove crianças que sumiram do feed (mata os processos).
  - Reinicia processos que morreram inesperadamente.

Fonte das crianças:
  - Preferida: GET $CHILDREN_URL (ex.: http://saferkids-api:8090/children.json)
  - Fallback:  $CHILDREN_FILE em YAML (formato {ip: {name, wg_pubkey}})
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# yaml é usado só pra fallback em arquivo — opcional.
try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# ── Config ──────────────────────────────────────────────────────────────────
RECORDINGS_DIR     = Path(os.getenv("RECORDINGS_DIR", "/recordings"))
SEGMENT_SECONDS    = int(os.getenv("SEGMENT_SECONDS", "600"))
INPUT_FRAMERATE    = int(os.getenv("INPUT_FRAMERATE", "60"))
UXPLAY_PREFIX      = os.getenv("UXPLAY_PREFIX", "saferkids")
RECONCILE_SECONDS  = int(os.getenv("RECONCILE_SECONDS", "20"))

CHILDREN_URL       = os.getenv("CHILDREN_URL", "")
CHILDREN_FEED_TOKEN = os.getenv("CHILDREN_FEED_TOKEN", "")
CHILDREN_FILE      = Path(os.getenv("CHILDREN_FILE", "/etc/saferkids/children.yaml"))

POD_NAME           = os.getenv("POD_NAME", "")           # saferkids-N (StatefulSet)
REPLICAS           = int(os.getenv("REPLICAS", "1"))     # tamanho do StatefulSet

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [supervisor] %(message)s",
)
log = logging.getLogger("saferkids.supervisor")


def pod_ordinal() -> int | None:
    """Extrai ordinal de POD_NAME=saferkids-N. None se desconhecido."""
    if not POD_NAME:
        return None
    m = re.search(r"-(\d+)$", POD_NAME)
    return int(m.group(1)) if m else None


# ── Modelos ─────────────────────────────────────────────────────────────────
@dataclass
class Child:
    id: int
    name: str
    wg_ip: str
    wg_pubkey: str = ""

    @property
    def safe_name(self) -> str:
        # Sanitiza para uso em path/Bonjour. Permite [-a-zA-Z0-9_].
        return re.sub(r"[^A-Za-z0-9_-]+", "-", self.name).strip("-") or f"child{self.id}"


@dataclass
class ChildRunner:
    child: Child
    uxplay: subprocess.Popen | None = None
    ffmpeg: subprocess.Popen | None = None
    fifo: Path | None = None
    started_at: float = field(default_factory=time.time)

    def stop(self) -> None:
        for p, label in ((self.ffmpeg, "ffmpeg"), (self.uxplay, "uxplay")):
            if p and p.poll() is None:
                log.info("[%s] parando %s (pid=%d)", self.child.safe_name, label, p.pid)
                try:
                    p.terminate()
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                except Exception as e:  # noqa: BLE001
                    log.warning("[%s] erro parando %s: %s", self.child.safe_name, label, e)
        if self.fifo and self.fifo.exists():
            try:
                self.fifo.unlink()
            except OSError:
                pass


# ── Carga do registry ───────────────────────────────────────────────────────
def fetch_children_http() -> list[Child] | None:
    if not CHILDREN_URL:
        return None
    req = urllib.request.Request(CHILDREN_URL)
    if CHILDREN_FEED_TOKEN:
        req.add_header("Authorization", f"Bearer {CHILDREN_FEED_TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception as e:  # noqa: BLE001
        log.warning("falha lendo CHILDREN_URL: %s", e)
        return None
    out: list[Child] = []
    for d in data:
        try:
            out.append(Child(
                id=int(d["id"]),
                name=str(d["name"]),
                wg_ip=str(d["wg_ip"]),
                wg_pubkey=str(d.get("wg_pubkey", "")),
            ))
        except (KeyError, ValueError) as e:
            log.warning("entrada inválida no feed: %s (%s)", d, e)
    return out


def fetch_children_file() -> list[Child]:
    if not (yaml and CHILDREN_FILE.is_file()):
        return []
    try:
        raw = yaml.safe_load(CHILDREN_FILE.read_text()) or {}
    except yaml.YAMLError as e:
        log.error("children.yaml inválido: %s", e)
        return []
    out: list[Child] = []
    # arquivo não tem `id` estável → usamos hash por IP pra sharding ser determinístico
    for ip, meta in raw.items():
        meta = meta or {}
        out.append(Child(
            id=meta.get("id") or (abs(hash(ip)) % 10_000_000),
            name=meta.get("name", str(ip)),
            wg_ip=str(ip),
            wg_pubkey=meta.get("wg_pubkey", ""),
        ))
    return sorted(out, key=lambda c: c.id)


def fetch_children() -> list[Child]:
    via_http = fetch_children_http()
    if via_http is not None:
        return via_http
    return fetch_children_file()


def assigned_to_me(children: list[Child]) -> list[Child]:
    ord_ = pod_ordinal()
    if ord_ is None or REPLICAS <= 1:
        return children
    return [c for c in children if (c.id % REPLICAS) == ord_]


# ── Spawn / supervise ───────────────────────────────────────────────────────
def spawn_runner(child: Child) -> ChildRunner | None:
    safe = child.safe_name
    fifo = Path(f"/tmp/uxplay-{safe}.fifo")
    if fifo.exists():
        fifo.unlink()
    os.mkfifo(fifo, mode=0o600)

    out_dir = RECORDINGS_DIR / safe
    out_dir.mkdir(parents=True, exist_ok=True)

    bonjour_name = f"{UXPLAY_PREFIX}-{safe}"
    log.info("[%s] iniciando UXPlay (Bonjour='%s', ip=%s)", safe, bonjour_name, child.wg_ip)

    uxplay_cmd = [
        "uxplay",
        "-n", bonjour_name,
        "-nh",
        "-vs", "0",     # sem janela
        "-as", "0",     # sem áudio playback
        "-vdmp", str(fifo),
    ]
    try:
        uxplay = subprocess.Popen(uxplay_cmd, stdout=sys.stdout, stderr=sys.stderr)
    except FileNotFoundError:
        log.error("binário uxplay não encontrado")
        fifo.unlink(missing_ok=True)
        return None

    # ffmpeg lê do FIFO e segmenta. Cada sessão dispara reabertura do FIFO,
    # gerando arquivos contíguos com timestamp da sessão no nome.
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_pattern = str(out_dir / f"{ts}_part_%03d.mp4")
    ffmpeg_cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "warning",
        "-fflags", "+genpts",
        "-f", "h264", "-framerate", str(INPUT_FRAMERATE),
        "-i", str(fifo),
        "-c:v", "copy",
        "-f", "segment",
        "-segment_time", str(SEGMENT_SECONDS),
        "-segment_format", "mp4",
        "-segment_format_options", "movflags=+faststart",
        "-reset_timestamps", "1",
        out_pattern,
    ]
    ffmpeg = subprocess.Popen(ffmpeg_cmd, stdout=sys.stdout, stderr=sys.stderr)

    return ChildRunner(child=child, uxplay=uxplay, ffmpeg=ffmpeg, fifo=fifo)


def reconcile(desired: list[Child], runners: dict[str, ChildRunner]) -> None:
    desired_keys = {c.safe_name: c for c in desired}

    # Stop runners não mais desejados.
    for key in list(runners):
        if key not in desired_keys:
            log.info("[%s] removida do registry → desligando", key)
            runners[key].stop()
            del runners[key]

    # Start runners faltando ou que morreram.
    for key, child in desired_keys.items():
        runner = runners.get(key)
        if runner is None:
            new = spawn_runner(child)
            if new:
                runners[key] = new
            continue
        # Já existe — verifica se algum subprocess morreu inesperadamente.
        for proc, label in ((runner.uxplay, "uxplay"), (runner.ffmpeg, "ffmpeg")):
            if proc and proc.poll() is not None:
                log.warning("[%s] %s morreu (rc=%s); reiniciando runner",
                            key, label, proc.returncode)
                runner.stop()
                new = spawn_runner(child)
                if new:
                    runners[key] = new
                break


# ── Avahi (Bonjour) ─────────────────────────────────────────────────────────
def start_avahi() -> None:
    """Garante D-Bus + avahi-daemon ativos pra UXPlay anunciar."""
    Path("/var/run/dbus").mkdir(exist_ok=True)
    Path("/var/run/dbus/pid").unlink(missing_ok=True)
    subprocess.run(["dbus-daemon", "--system", "--fork"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Cria usuário avahi se não existir.
    if subprocess.run(["id", "-u", "avahi"], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        subprocess.run(["useradd", "--system", "--no-create-home",
                        "--shell", "/usr/sbin/nologin", "avahi"], check=False)
    Path("/var/run/avahi-daemon").mkdir(exist_ok=True)
    subprocess.run(["chown", "-R", "avahi:avahi", "/var/run/avahi-daemon"], check=False)
    subprocess.run(["avahi-daemon", "--daemonize"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ── Main ────────────────────────────────────────────────────────────────────
def main() -> int:
    RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
    start_avahi()

    runners: dict[str, ChildRunner] = {}

    def shutdown(_signum, _frame):
        log.info("sinal recebido → desligando todos os runners")
        for r in list(runners.values()):
            r.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info("supervisor iniciado | POD_NAME=%s ordinal=%s replicas=%d",
             POD_NAME or "(none)", pod_ordinal(), REPLICAS)

    while True:
        try:
            children = fetch_children()
            mine = assigned_to_me(children)
            log.debug("registry=%d, atribuídas a este pod=%d",
                      len(children), len(mine))
            reconcile(mine, runners)
        except Exception:  # noqa: BLE001
            log.exception("erro no ciclo de reconcile")
        time.sleep(RECONCILE_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
