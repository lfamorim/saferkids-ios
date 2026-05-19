# saferkids-ios

> Recebe streaming de tela do iPhone/iPad da criança via VPN, grava em arquivos MP4 e envia para uma IA analisar se o uso do dispositivo está sendo **seguro** ou não.

```
 iPhone/iPad ──WireGuard VPN──▶ Servidor Linux ──▶ UXPlay (receptor AirPlay)
                                                 └▶ ffmpeg (segmenta em MP4)
                                                            │
                                                            ▼
                                                    Pipeline de IA
                                          (classifica uso seguro / inseguro)
```

Stack 100% open-source, em Docker Compose, pensado para rodar em um VPS Linux barato.

---

## Para que serve

`saferkids-ios` é uma ferramenta de **supervisão parental técnica**. O responsável instala um perfil de VPN no iPhone/iPad da criança; quando a criança ativa o **Espelhamento de Tela**, o vídeo é transmitido pelo túnel VPN até o servidor, gravado em MP4 e disponibilizado para um modelo de IA classificar o conteúdo (ex.: jogos apropriados, redes sociais, conteúdo adulto, contatos com estranhos, tempo excessivo em determinado app, etc.).

Os arquivos ficam em pedaços curtos (padrão 10 min) para que a IA possa analisar **quase em tempo real**, sem precisar esperar a sessão inteira terminar.

> ⚠️ **Aviso legal e ético**: use somente em dispositivos sob sua responsabilidade legal (filhos menores de idade) e com transparência adequada à idade. Verifique a legislação local sobre monitoramento de menores antes de implantar.

---

> 🛡️ Inclui também um **detector de evasão**: se o iPhone está ligado mas a
> VPN/AirPlay foram desligados, os pais recebem alerta no Telegram (ou
> webhook). Detalhes em [`docs/anti-evasion.md`](docs/anti-evasion.md).

## Componentes

- **VPN — `wg-easy`**: WireGuard com interface web. Gera um QR Code que a criança escaneia **uma única vez** no app **WireGuard** da App Store.
- **API — FastAPI + SQLite (`api/`)**: CRUD de crianças. Aloca IPs `/32` automaticamente. É a fonte da verdade que monitor e supervisor consomem.
- **Supervisor — `uxplay/supervisor.py`**: dentro do Pod, faz spawn de **N processos UXPlay simultâneos** (1 por criança designada), cada um com nome Bonjour próprio (`saferkids-<nome>`) e ffmpeg dedicado segmentando MP4 sob `recordings/<nome>/`.
- **Monitor — `monitor/monitor.py`**: detecta evasão por criança (state machine RECORDING/IDLE/DARK/OFFLINE), alerta via Telegram/Webhook, expõe `/heartbeat`, `/status`, `/metrics`.
- **Pasta `recordings/<nome>/<sessao>/*.mp4`**: pronta para pipelines de IA por criança.

---

## Requisitos

- Servidor Linux com IP público ou DNS (um VPS de US$ 5/mês resolve).
- Docker e Docker Compose v2.
- Porta UDP **51820** (WireGuard) e TCP **51821** (UI web do wg-easy) acessíveis pelo iPhone.
- Não é necessário abrir nenhuma porta de AirPlay: o tráfego viaja **dentro** do túnel VPN.

---

## 1. Configuração

```bash
cp .env.example .env

# Gera o hash bcrypt da senha do painel wg-easy:
docker run --rm ghcr.io/wg-easy/wg-easy:14 wgpw 'SuaSenhaForte'

# Cole o hash em WG_PASSWORD_HASH (escape cada $ como $$ no docker-compose).
$EDITOR .env
```

Variáveis principais (`.env`):

- `WG_HOST` — hostname/IP público do servidor.
- `WG_PASSWORD_HASH` — hash bcrypt da senha do painel.
- `UXPLAY_NAME` — nome que aparece no menu de Espelhamento de Tela do iPhone (ex.: `saferkids`).
- `SEGMENT_SECONDS` — duração de cada MP4 (padrão `600` = 10 minutos).

## 2. Subir o stack

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f uxplay
```

## 3. Cadastrar a criança na API

A API CRUD escuta em `:8090` (host network).

```bash
# (opcional) protege com Bearer token
export API_TOKEN="$(openssl rand -hex 24)"   # também coloque em .env

# cria — IP /32 alocado automaticamente do range WG_IP_RANGE
curl -sS -X POST http://localhost:8090/children \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"ana"}'
# → {"id":1,"name":"ana","wg_ip":"10.8.0.2",...}

curl -sS http://localhost:8090/children -H "Authorization: Bearer $API_TOKEN"
curl -sS -X DELETE http://localhost:8090/children/1 -H "Authorization: Bearer $API_TOKEN"
```

Depois disso, vá ao `wg-easy` (`:51821`), crie um peer WireGuard atribuindo o **mesmo IP** que a API alocou (e copie a `wg_pubkey` retornada de volta com `PATCH /children/1` se quiser cross-check). O supervisor detecta a entrada em ≤20s e sobe um receiver AirPlay chamado `saferkids-ana`.

## 4. Configurar o iPhone/iPad da criança (uma única vez)

1. Instale o app gratuito **WireGuard** na App Store.
2. No computador, abra `http://<ip-do-servidor>:51821` e faça login.
3. Clique em **+ New Client** → dê um nome (ex.: `iphone-da-ana`) → aparece um **QR Code**.
4. No app WireGuard do iOS: **Adicionar túnel → Criar a partir de QR Code** → escaneie.
5. Ative o túnel. O dispositivo passa a ter um IP `10.8.0.x` na VPN.

> Dica: para que o túnel fique sempre ligado, ative **"Conectar sob demanda"** no perfil do WireGuard no iOS (em *Configurações → VPN*).

## 5. Gravar uma sessão

1. Com o WireGuard ligado, abra a **Central de Controle** no iPhone/iPad.
2. Toque em **Espelhamento de Tela**.
3. Selecione **`saferkids-ana`** (o nome é `<UXPLAY_PREFIX>-<nome-da-criança>`).
4. A tela passa a ser transmitida ao servidor. Os arquivos aparecem em:

```
recordings/ana/<AAAAMMDD_HHMMSS>_part_000.mp4
recordings/ana/<AAAAMMDD_HHMMSS>_part_001.mp4
recordings/bob/<AAAAMMDD_HHMMSS>_part_000.mp4   # outra criança, em paralelo
```

5. Tocar em **Parar Espelhamento** finaliza o último MP4 automaticamente; uma nova sessão cria uma nova pasta.

## 6. Análise pela IA

Cada MP4 é independente, com cabeçalho `+faststart`, e pode ser consumido assim que finalizado. Exemplo de gancho simples — observa a pasta e dispara seu modelo:

```bash
# Exemplo: extrai 1 frame por segundo para enviar a um VLM
ffmpeg -i recordings/20260519_142233/20260519_142233_part_000.mp4 \
       -vf fps=1 frames/%04d.png

# Ou use inotifywait para reagir em tempo quase real:
inotifywait -m -e close_write --format '%w%f' recordings/ |
while read -r mp4; do
    python analyze.py "$mp4"     # seu pipeline de IA aqui
done
```

O `analyze.py` (não incluído neste repositório) é o ponto onde você pluga o classificador de uso seguro: pode ser um modelo local (ex.: Llava, Qwen-VL), uma API (OpenAI, Gemini, Claude), regras simples sobre OCR de tela, etc.

---

## Solução de problemas

- **iPhone não enxerga o `saferkids` no menu de Espelhamento** — o Bonjour precisa ser anunciado na interface `wg0`. Verifique:
  ```bash
  ip -br addr show wg0
  docker compose exec uxplay avahi-browse -at | grep -i airplay
  ```
- **Vídeo travado / acelerado** — o iOS pode espelhar a 30 fps em vez de 60. Ajuste `INPUT_FRAMERATE` em `uxplay/recorder.sh`.
- **`-vdmp` não reconhecido** — UXPlay anterior à 1.66. O `Dockerfile` está fixado em `UXPLAY_VERSION=1.68`; reconstrua com `docker compose build --no-cache uxplay`.
- **Quero rotear todo o tráfego do iPhone pela VPN** — em `docker-compose.yml`, troque `WG_ALLOWED_IPS=10.8.0.0/24` por `WG_ALLOWED_IPS=0.0.0.0/0, ::/0` (modo *full-tunnel*; também permite filtrar/loggar DNS no servidor).

## Segurança e privacidade

- Use uma senha forte em `WG_PASSWORD_HASH`. O painel wg-easy é admin total da VPN.
- Restrinja a porta TCP 51821 ao seu IP por firewall, ou coloque atrás de um proxy reverso com TLS + autenticação.
- A pasta `recordings/` contém **a tela da criança** — proteja com permissões restritas, criptografia em disco e política de retenção (ex.: apagar MP4s após N dias / após análise).
- Logs da IA também são sensíveis; trate-os como dados pessoais de menor de idade (LGPD no Brasil).

---

## Deploy em produção: Google Cloud (GKE) + GitHub Actions

A pasta `infra/` e `k8s/` contêm tudo para subir o stack em um cluster GKE
com CI/CD pelo GitHub.

### Arquitetura

- **Artifact Registry** (`saferkids/uxplay`) — imagem do receptor é construída e publicada pelo CI.
- **GKE Standard** (não Autopilot) com node pool dedicado `saferkids-pool` *tainted* — necessário porque o Pod usa `hostNetwork`, `privileged` e capacidade `SYS_MODULE` para o WireGuard.
- **StatefulSet `saferkids`** com 2 containers no mesmo Pod (`wg-easy` + `uxplay`) compartilhando a stack de rede do nó. Assim a interface `wg0` criada pelo `wg-easy` é vista pelo Avahi/UXPlay e pode anunciar o AirPlay para o iPhone via Bonjour.
- **Service `saferkids-vpn`** do tipo `LoadBalancer` UDP/51820 — IP público da VPN.
- **PVCs** `saferkids-recordings` (100Gi pd-balanced) e `saferkids-wg-data` (1Gi).
- **Workload Identity Federation** GitHub ↔ GCP — pipeline autentica sem chave JSON.

### 1. Bootstrap (uma vez)

```bash
GCP_PROJECT_ID=meu-projeto \
GH_REPO=org/saferkids-ios \
./infra/gcloud-bootstrap.sh
```

O script cria APIs, Artifact Registry, cluster GKE, node pool com taint, Service Account de deploy, Workload Identity Pool/Provider amarrado ao seu repo, e regras de firewall para AirPlay + WireGuard. Ao final imprime os valores que você deve cadastrar no GitHub.

### 2. GitHub — Variables (Settings → Actions → Variables)

| Nome             | Exemplo                                                              |
| ---------------- | -------------------------------------------------------------------- |
| `GCP_PROJECT_ID` | `meu-projeto`                                                        |
| `GCP_REGION`     | `southamerica-east1`                                                 |
| `GKE_CLUSTER`    | `saferkids`                                                          |
| `GKE_LOCATION`   | `southamerica-east1-a`                                               |
| `AR_REPOSITORY`  | `saferkids`                                                          |
| `WIF_PROVIDER`   | `projects/123/locations/global/workloadIdentityPools/gh/providers/gh`|
| `DEPLOY_SA`      | `github-deployer@meu-projeto.iam.gserviceaccount.com`                |

### 3. GitHub — Secret

`SAFERKIDS_SECRET_JSON`:
```json
{"WG_HOST":"vpn.example.com","WG_PASSWORD_HASH":"$2a$12$...","UXPLAY_NAME":"saferkids","SEGMENT_SECONDS":"600"}
```

### 4. Workflows

- **`.github/workflows/ci.yml`** — em PRs/branches: shellcheck, hadolint, yamllint e build de validação da imagem (sem push).
- **`.github/workflows/deploy.yml`** — em push para `main`: autentica via WIF, constrói e publica a imagem do `uxplay` no Artifact Registry, sincroniza o `Secret` no cluster, faz `kustomize edit set image` com o SHA do commit, aplica `k8s/` e espera o rollout do StatefulSet, ao final imprime o IP público da VPN.

### 5. Pós-deploy

```bash
# IP público da VPN (usado em WG_HOST se quiser fixar):
kubectl -n saferkids get svc saferkids-vpn

# Acessar a UI do wg-easy localmente (não exponha publicamente sem TLS+auth):
kubectl -n saferkids port-forward svc/saferkids-ui 51821:51821
# → http://localhost:51821
```

### Observações importantes

- **Autopilot não funciona** para esse workload (bloqueia `privileged`, `hostNetwork`, `hostPort`). Use sempre GKE *Standard*.
- **AirPlay sobre VPN**: como o iPhone fica em `10.8.0.0/24` quando conectado e o `wg0` existe no host, o Bonjour do Avahi anuncia o receptor diretamente para a sub-rede VPN. Não é necessário `mdns-reflector`.
- **Custos**: a parte mais cara é o LoadBalancer L4 + o disco persistente das gravações. Defina retenção (ex.: cron deletando MP4s > 7 dias) — exemplo a adicionar como CronJob futuramente.

---

## Licença

Os componentes têm licenças próprias (UXPlay GPL-3.0, wg-easy GPL-2.0, ffmpeg LGPL/GPL). Os scripts deste repositório são liberados sob MIT.
