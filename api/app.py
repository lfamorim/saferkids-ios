"""
saferkids — API CRUD de crianças.

Endpoints (auth: header `Authorization: Bearer $API_TOKEN`):
  POST   /children              cria criança (auto-aloca IP /32 se omitido)
  GET    /children              lista todas
  GET    /children/{id}         detalhe
  PATCH  /children/{id}         atualiza name/wg_pubkey/notes
  DELETE /children/{id}         remove

Endpoint consumido pelos Pods (auth: bearer $CHILDREN_FEED_TOKEN, opcional):
  GET    /children.yaml         feed YAML compatível com supervisor/monitor

Health:
  GET    /healthz
"""
from __future__ import annotations

import ipaddress
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import logging

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from sqlalchemy.exc import OperationalError
from sqlmodel import Field, Session, SQLModel, create_engine, select

from wg_easy import WgEasyClient, WgEasyError

log = logging.getLogger("saferkids.api")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")

# ── Config ──────────────────────────────────────────────────────────────────
DB_URL       = os.getenv("DATABASE_URL", "sqlite:////data/saferkids.db")
API_TOKEN    = os.getenv("API_TOKEN", "")
FEED_TOKEN   = os.getenv("CHILDREN_FEED_TOKEN", "")
WG_IP_RANGE  = os.getenv("WG_IP_RANGE", "10.8.0.2-10.8.0.254")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
)

wg = WgEasyClient()


# ── Models ──────────────────────────────────────────────────────────────────
class Child(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    wg_ip: str = Field(index=True, unique=True)
    wg_pubkey: str | None = None
    wg_easy_id: str | None = Field(default=None, index=True)  # uuid do peer no wg-easy
    notes: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChildCreate(SQLModel):
    name: str
    wg_pubkey: str | None = None
    wg_ip: str | None = None  # se vazio: aloca o próximo /32 livre
    notes: str | None = None


class ChildUpdate(SQLModel):
    name: str | None = None
    wg_pubkey: str | None = None
    notes: str | None = None


# ── Helpers ─────────────────────────────────────────────────────────────────
def _auth(authorization: str = Header(default="")) -> None:
    if not API_TOKEN:
        return  # auth desligada em dev
    expected = f"Bearer {API_TOKEN}"
    if not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


def _alloc_ip(s: Session) -> str:
    try:
        start_s, end_s = WG_IP_RANGE.split("-")
        start = int(ipaddress.IPv4Address(start_s.strip()))
        end = int(ipaddress.IPv4Address(end_s.strip()))
    except (ValueError, ipaddress.AddressValueError) as e:
        raise HTTPException(500, f"WG_IP_RANGE inválido: {e}")
    used = {c.wg_ip for c in s.exec(select(Child)).all()}
    for i in range(start, end + 1):
        ip = str(ipaddress.IPv4Address(i))
        if ip not in used:
            return ip
    raise HTTPException(409, "WG_IP_RANGE esgotado")


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        raise HTTPException(400, f"wg_ip inválido: {ip}")


# ── Lifecycle ───────────────────────────────────────────────────────────────
def _migrate() -> None:
    """Adiciona colunas novas em DBs antigos (idempotente)."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.begin() as conn:
        try:
            conn.exec_driver_sql("ALTER TABLE child ADD COLUMN wg_easy_id TEXT")
            log.info("migration: coluna wg_easy_id adicionada")
        except OperationalError:
            pass  # já existe


@asynccontextmanager
async def lifespan(_app: FastAPI):
    SQLModel.metadata.create_all(engine)
    _migrate()
    log.info("wg-easy: %s", f"ativo ({wg.base_url})" if wg.enabled else "desativado (modo manual)")
    yield


app = FastAPI(title="saferkids API", version="0.1.0", lifespan=lifespan)


# ── Endpoints públicos ──────────────────────────────────────────────────────
@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.post("/children", status_code=201, dependencies=[Depends(_auth)])
def create_child(payload: ChildCreate) -> Child:
    """
    Cria a criança e, se WG_EASY_URL estiver configurado, já provisiona o
    peer WireGuard automaticamente — o IP/pubkey são decididos pelo wg-easy
    e gravados aqui. Sem WG_EASY_URL, cai no modo manual (allocator local).
    """
    if payload.wg_ip:
        _validate_ip(payload.wg_ip)

    wg_easy_id: str | None = None
    wg_ip: str | None = payload.wg_ip
    wg_pubkey: str | None = payload.wg_pubkey

    if wg.enabled:
        try:
            peer = wg.create_client(payload.name)
        except WgEasyError as e:
            raise HTTPException(502, f"wg-easy: {e}")
        wg_easy_id = str(peer.get("id") or "")
        # 'address' costuma vir como '10.8.0.5'; algumas builds usam 'addresses'.
        wg_ip = peer.get("address") or peer.get("addresses") or wg_ip
        if isinstance(wg_ip, list):
            wg_ip = wg_ip[0]
        if wg_ip:
            wg_ip = str(wg_ip).split("/")[0]
        wg_pubkey = peer.get("publicKey") or wg_pubkey

    with Session(engine) as s:
        if not wg_ip:
            wg_ip = _alloc_ip(s)
        child = Child(
            name=payload.name,
            wg_ip=wg_ip,
            wg_pubkey=wg_pubkey,
            wg_easy_id=wg_easy_id,
            notes=payload.notes,
        )
        s.add(child)
        try:
            s.commit()
        except Exception as e:  # noqa: BLE001
            # Rollback: remove o peer recém-criado no wg-easy se a inserção falhou.
            if wg_easy_id:
                try:
                    wg.delete_client(wg_easy_id)
                except WgEasyError:
                    log.exception("falha removendo peer órfão %s", wg_easy_id)
            raise HTTPException(409, f"conflito: {e}")
        s.refresh(child)
        return child


@app.get("/children", dependencies=[Depends(_auth)])
def list_children() -> list[Child]:
    with Session(engine) as s:
        return list(s.exec(select(Child).order_by(Child.id)).all())


@app.get("/children/{child_id}", dependencies=[Depends(_auth)])
def get_child(child_id: int) -> Child:
    with Session(engine) as s:
        c = s.get(Child, child_id)
        if not c:
            raise HTTPException(404, "criança não encontrada")
        return c


@app.patch("/children/{child_id}", dependencies=[Depends(_auth)])
def update_child(child_id: int, payload: ChildUpdate) -> Child:
    with Session(engine) as s:
        c = s.get(Child, child_id)
        if not c:
            raise HTTPException(404)
        data = payload.model_dump(exclude_unset=True)
        for k, v in data.items():
            setattr(c, k, v)
        s.add(c)
        try:
            s.commit()
        except Exception as e:  # noqa: BLE001
            raise HTTPException(409, f"conflito: {e}")
        s.refresh(c)
        return c


@app.delete("/children/{child_id}", status_code=204, dependencies=[Depends(_auth)])
def delete_child(child_id: int) -> Response:
    with Session(engine) as s:
        c = s.get(Child, child_id)
        if not c:
            raise HTTPException(404)
        wg_easy_id = c.wg_easy_id
        s.delete(c)
        s.commit()
    if wg_easy_id and wg.enabled:
        try:
            wg.delete_client(wg_easy_id)
        except WgEasyError as e:
            log.warning("criança %d removida do DB, mas wg-easy falhou: %s", child_id, e)
    return Response(status_code=204)


@app.get("/children/{child_id}/config", dependencies=[Depends(_auth)])
def get_child_config(child_id: int) -> Response:
    """Retorna o arquivo .conf do WireGuard (texto). Útil para colar no app desktop."""
    with Session(engine) as s:
        c = s.get(Child, child_id)
    if not c:
        raise HTTPException(404)
    if not c.wg_easy_id or not wg.enabled:
        raise HTTPException(409, "peer não foi provisionado pelo wg-easy (modo manual)")
    try:
        conf = wg.get_configuration(c.wg_easy_id)
    except WgEasyError as e:
        raise HTTPException(502, f"wg-easy: {e}")
    return Response(
        content=conf,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{c.name}.conf"'},
    )


@app.get("/children/{child_id}/qrcode", dependencies=[Depends(_auth)])
def get_child_qrcode(child_id: int) -> Response:
    """Retorna o QR Code SVG — escaneie no app WireGuard do iOS."""
    with Session(engine) as s:
        c = s.get(Child, child_id)
    if not c:
        raise HTTPException(404)
    if not c.wg_easy_id or not wg.enabled:
        raise HTTPException(409, "peer não foi provisionado pelo wg-easy (modo manual)")
    try:
        svg = wg.get_qrcode_svg(c.wg_easy_id)
    except WgEasyError as e:
        raise HTTPException(502, f"wg-easy: {e}")
    return Response(content=svg, media_type="image/svg+xml")


# ── Feed consumido pelos Pods ───────────────────────────────────────────────
@app.get("/children.yaml")
def children_yaml(authorization: str = Header(default="")) -> Response:
    if FEED_TOKEN:
        if not secrets.compare_digest(authorization, f"Bearer {FEED_TOKEN}"):
            raise HTTPException(401)
    with Session(engine) as s:
        children = s.exec(select(Child).order_by(Child.id)).all()
    out = {
        c.wg_ip: {
            "name": c.name,
            "wg_pubkey": c.wg_pubkey or "",
            "id": c.id,
        }
        for c in children
    }
    return Response(
        content=yaml.safe_dump(out, sort_keys=True, allow_unicode=True),
        media_type="application/yaml",
    )


# ── JSON list ordenada (usada pelo supervisor pra sharding por ordinal) ─────
@app.get("/children.json")
def children_json(authorization: str = Header(default="")) -> list[dict]:
    if FEED_TOKEN:
        if not secrets.compare_digest(authorization, f"Bearer {FEED_TOKEN}"):
            raise HTTPException(401)
    with Session(engine) as s:
        children = s.exec(select(Child).order_by(Child.id)).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "wg_ip": c.wg_ip,
            "wg_pubkey": c.wg_pubkey or "",
        }
        for c in children
    ]
