"""
Cliente síncrono mínimo da API REST do wg-easy (v14+).

Endpoints usados:
  POST   /api/session                                     login (cookie session)
  GET    /api/wireguard/client                            lista
  POST   /api/wireguard/client                            cria  (body: {name})
  DELETE /api/wireguard/client/{id}                       remove
  GET    /api/wireguard/client/{id}/configuration         .conf
  GET    /api/wireguard/client/{id}/qrcode.svg            QR SVG

A wg-easy escolhe o IP /32 disponível no range que ela mesma controla
(WG_DEFAULT_ADDRESS=10.8.0.x). Nossa API apenas registra o IP retornado.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

log = logging.getLogger("saferkids.wg_easy")

WG_EASY_URL      = os.getenv("WG_EASY_URL", "")
WG_EASY_PASSWORD = os.getenv("WG_EASY_PASSWORD", "")
WG_EASY_TIMEOUT  = float(os.getenv("WG_EASY_TIMEOUT", "10"))


class WgEasyError(RuntimeError):
    """Erro de comunicação ou de protocolo com o wg-easy."""


class WgEasyClient:
    """
    Sessão persistente com login lazy. Reautentica automaticamente em 401.
    Use uma única instância por processo (cookie da sessão fica no httpx.Client).
    """

    def __init__(self, base_url: str = "", password: str = "") -> None:
        self.base_url = (base_url or WG_EASY_URL).rstrip("/")
        self.password = password or WG_EASY_PASSWORD
        self._client = httpx.Client(timeout=WG_EASY_TIMEOUT, follow_redirects=False)
        self._logged_in = False

    # ── Internos ────────────────────────────────────────────────────────────
    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.password)

    def _login(self) -> None:
        r = self._client.post(
            f"{self.base_url}/api/session",
            json={"password": self.password},
        )
        if r.status_code >= 400:
            raise WgEasyError(f"login wg-easy falhou: HTTP {r.status_code} {r.text[:200]}")
        self._logged_in = True

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        if not self.enabled:
            raise WgEasyError("WG_EASY_URL/WG_EASY_PASSWORD não configurados")
        if not self._logged_in:
            self._login()
        url = f"{self.base_url}{path}"
        r = self._client.request(method, url, **kwargs)
        if r.status_code == 401:
            # Sessão expirou — relogin uma vez e tenta de novo.
            self._logged_in = False
            self._login()
            r = self._client.request(method, url, **kwargs)
        return r

    # ── API pública ─────────────────────────────────────────────────────────
    def list_clients(self) -> list[dict]:
        r = self._request("GET", "/api/wireguard/client")
        if r.status_code >= 400:
            raise WgEasyError(f"list_clients HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    def create_client(self, name: str) -> dict:
        r = self._request("POST", "/api/wireguard/client", json={"name": name})
        if r.status_code >= 400:
            raise WgEasyError(f"create_client HTTP {r.status_code}: {r.text[:200]}")
        # Algumas versões retornam o cliente, outras só {"success": true}.
        # Como fallback, encontramos pelo nome.
        try:
            data = r.json()
        except ValueError:
            data = {}
        if isinstance(data, dict) and data.get("id"):
            return data
        for c in self.list_clients():
            if c.get("name") == name:
                return c
        raise WgEasyError(f"cliente '{name}' criado mas não encontrado na listagem")

    def delete_client(self, client_id: str) -> None:
        r = self._request("DELETE", f"/api/wireguard/client/{client_id}")
        if r.status_code >= 400 and r.status_code != 404:
            raise WgEasyError(f"delete_client HTTP {r.status_code}: {r.text[:200]}")

    def get_configuration(self, client_id: str) -> str:
        r = self._request("GET", f"/api/wireguard/client/{client_id}/configuration")
        if r.status_code >= 400:
            raise WgEasyError(f"configuration HTTP {r.status_code}: {r.text[:200]}")
        return r.text

    def get_qrcode_svg(self, client_id: str) -> bytes:
        r = self._request("GET", f"/api/wireguard/client/{client_id}/qrcode.svg")
        if r.status_code >= 400:
            raise WgEasyError(f"qrcode HTTP {r.status_code}: {r.text[:200]}")
        return r.content
