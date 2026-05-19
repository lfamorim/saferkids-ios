# Detecção de evasão (VPN/AirPlay desligados com iPhone ligado)

Este documento explica como o `saferkids-ios` detecta o caso "criança desligou
a VPN para escapar do monitoramento" e como reduzir falsos negativos.

## Insight central

Com **"Conectar sob Demanda"** ligado no app WireGuard do iOS, o túnel
**reativa sozinho** sempre que há rede. Então:

- **Handshake WG recente** ⇒ iPhone ligado e online (não precisa heartbeat só
  pra saber isso).
- **VPN ligada + AirPlay desligado** = a criança está usando o iPhone, mas
  **não estamos vendo a tela** → este é o caso clássico de evasão (criança
  parou o espelhamento mas continua mexendo no celular). É o alerta principal.
- **VPN desligada com heartbeat externo recente** = tunel removido manualmente.
- **VPN desligada sem heartbeat** = telefone provavelmente offline, sem alerta.

## Modelo de estados (no serviço `monitor`)

Para cada peer WireGuard, a cada `POLL_SECONDS`:

| Estado       | WG handshake             | AirPlay  | Alerta?                                      |
| ------------ | ------------------------ | -------- | -------------------------------------------- |
| `RECORDING`  | < `DARK_AFTER`           | ativo    | ✅ ok, gravando                              |
| **`IDLE`**   | < `DARK_AFTER`           | inativo  | 🚨 sim, após `IDLE_GRACE` (default 5 min)    |
| **`DARK`**   | ≥ `DARK_AFTER` + heartbeat OU < `OFFLINE_AFTER` | — | 🚨 sim, imediato        |
| `OFFLINE`    | ≥ `OFFLINE_AFTER`, sem heartbeat | —    | ⚪ silencioso (telefone provavelmente off)   |

Defaults: `DARK_AFTER=120s`, `IDLE_GRACE=300s`, `OFFLINE_AFTER=1800s`. Tudo
ajustável por env var. Alertas só disparam dentro da `USAGE_WINDOW`
(default `07:00-22:00`, fuso `America/Sao_Paulo`) — fora dela o monitor fica
silencioso para não acordar os pais à toa.

> Conclusão prática: o **heartbeat externo é opcional**. Sem ele, `IDLE` já
> cobre o caso "criança com o celular mas sem AirPlay", e `DARK` ainda é
> detectável (só não dá para distinguir de `OFFLINE` após 30 min).

## Sinais usados

1. **WireGuard handshake** — `wg show wg0 dump`. Como `PersistentKeepalive=25s`
   está ligado pelo `wg-easy`, um peer ativo bate handshake a cada 25s.
2. **AirPlay ativo** — `mtime` do MP4 mais recente em `recordings/`. Se foi
   atualizado há menos de `AIRPLAY_FRESH_SECONDS` (padrão 60s), está gravando.
3. **mtime do MP4 da criança** — `RECORDINGS_DIR/<nome-da-criança>/...mp4`.
   Sessão AirPlay ativa = ffmpeg está escrevendo no MP4. Como cada criança
   tem sua própria subpasta (criada pelo supervisor), conseguimos saber
   quem está mirrorando agora mesmo com várias sessões simultâneas.
4. **Heartbeat externo opcional** — `GET /heartbeat?token=…` vindo do iPhone
   *fora* da VPN (Atalho iOS). Permite distinguir **DARK** (telefone online
   sem VPN) de **OFFLINE** (telefone realmente desligado/sem rede).

## Configurando o Atalho iOS de heartbeat (camada chave)

Crie no iPhone da criança, **uma vez**, no app **Atalhos**:

1. **Novo Atalho** → adicione a ação **Obter conteúdo de URL**
   - URL: `https://heartbeat.seudominio.com/heartbeat?token=COLE_O_HEARTBEAT_TOKEN_AQUI`
   - Método: `GET`
2. Salve como `saferkids heartbeat`.
3. Vá em **Automação → Automação Pessoal → Criar**:
   - Gatilho: **Hora do dia**, **a cada 15 minutos** (ou no menor intervalo
     possível na sua versão do iOS).
   - Ação: **Executar Atalho → saferkids heartbeat**.
   - **Importante**: desmarque "Perguntar antes de executar" (aparece em
     dispositivo **supervisionado**; em iOS comum requer toque na notificação).
4. Crie outra automação com gatilho **Ao desbloquear** → mesmo atalho.

Se o iPhone está supervisionado, o atalho roda silenciosamente. Em iPhone não
supervisionado, ele ainda roda mas pode pedir confirmação — é melhor que nada.

## Camada de prevenção: perfil de configuração com VPN On-Demand

Para impedir que a criança simplesmente **desligue** o WireGuard, gere um
**Configuration Profile** (.mobileconfig) com regras `OnDemandRules → Connect`
abrangentes. Em telefone **supervisionado** (via Apple Configurator no Mac),
o perfil é marcado como não removível pelo usuário.

Esqueleto (a customizar com sua chave WireGuard, peer key, endpoint):

```xml
<key>OnDemandEnabled</key><integer>1</integer>
<key>OnDemandRules</key>
<array>
  <dict>
    <key>Action</key><string>Connect</string>
    <key>InterfaceTypeMatch</key><string>WiFi</string>
  </dict>
  <dict>
    <key>Action</key><string>Connect</string>
    <key>InterfaceTypeMatch</key><string>Cellular</string>
  </dict>
</array>
```

Use a ferramenta `wg-quick` ou o app oficial WireGuard no Mac para exportar o
perfil base, depois injete o bloco `OnDemandRules` acima e assine se possível.

## Canais de alerta

Configure **ao menos um** dos dois no `.env` (ou no Secret K8s):

- **Telegram bot** (mais simples): `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`.
- **Webhook genérico** (Discord/Slack/n8n): `ALERT_WEBHOOK_URL`.

Mensagem típica:

```
🚨 saferkids-ios — possível evasão detectada
Peer: iphone-da-ana
Estado: IDLE → DARK
Motivo: WG sem handshake mas heartbeat do Atalho iOS continua chegando
Última handshake WG: 4min atrás
Heartbeat externo: 1min atrás
```

## Endpoints HTTP do monitor

| Caminho       | Descrição                                                     |
| ------------- | ------------------------------------------------------------- |
| `/heartbeat`  | recebe pings do Atalho iOS (precisa de `?token=`)             |
| `/status`     | JSON com estado de cada peer (para dashboards)                |
| `/metrics`    | Prometheus (`saferkids_peer_state`, `*_age_seconds`)          |

Em K8s, expostos pelo Service `saferkids-monitor` (NodePort). Para o
heartbeat funcionar via Atalho iOS é preciso TLS público — recomendo um
`Ingress` GCE com `ManagedCertificate` apontando para o domínio
`heartbeat.seudominio.com`.

## Limites honestos

- Se o iPhone for **desligado** (botão lateral) ou **modo avião** + fora de
  Wi-Fi, *nenhum* sinal chega. Vai aparecer como `OFFLINE` — indistinguível
  de "criança desligou e escondeu o aparelho". Política sugerida: configurar
  alerta também para `OFFLINE` durante períodos esperados de uso.
- O Atalho iOS pode ser **deletado** pela criança em iPhone não supervisionado.
  Por isso a camada de **supervisão + perfil bloqueado** é o que dá garantia
  real. Sem supervisão, o sistema é "best-effort" — bom o suficiente para
  flagrar a maioria das tentativas casuais.
