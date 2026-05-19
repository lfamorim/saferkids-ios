#!/usr/bin/env bash
# Bootstrap idempotente do Google Cloud para o projeto saferkids-ios.
#
# Cria:
#   1. APIs habilitadas
#   2. Artifact Registry (Docker)                     → onde o CI publica a imagem
#   3. Cluster GKE Standard                           → Autopilot NÃO serve (precisa de privileged + hostNetwork)
#   4. Node pool dedicado "saferkids-pool" com taint  → para o StatefulSet
#   5. Service Account de deploy + Workload Identity Federation com o GitHub
#
# Execute uma vez, com: GCP_PROJECT_ID=... GH_REPO=org/repo ./infra/gcloud-bootstrap.sh
set -euo pipefail

: "${GCP_PROJECT_ID:?defina GCP_PROJECT_ID}"
: "${GH_REPO:?defina GH_REPO no formato 'org/repo'}"
: "${GCP_REGION:=southamerica-east1}"
: "${GCP_ZONE:=${GCP_REGION}-a}"
: "${GKE_CLUSTER:=saferkids}"
: "${AR_REPOSITORY:=saferkids}"
: "${NODE_POOL:=saferkids-pool}"
: "${POOL_NAME:=gh}"          # Workload Identity Pool
: "${PROVIDER_NAME:=gh}"      # Workload Identity Provider
: "${DEPLOY_SA_NAME:=github-deployer}"

echo "▶ Projeto: $GCP_PROJECT_ID  | Região: $GCP_REGION  | Repo GitHub: $GH_REPO"
gcloud config set project "$GCP_PROJECT_ID"

# 1) APIs ─────────────────────────────────────────────────────────────────────
gcloud services enable \
    container.googleapis.com \
    artifactregistry.googleapis.com \
    iamcredentials.googleapis.com \
    iam.googleapis.com \
    compute.googleapis.com

# 2) Artifact Registry ────────────────────────────────────────────────────────
gcloud artifacts repositories describe "$AR_REPOSITORY" --location="$GCP_REGION" >/dev/null 2>&1 || \
    gcloud artifacts repositories create "$AR_REPOSITORY" \
        --repository-format=docker --location="$GCP_REGION" \
        --description="Imagens do saferkids-ios"

# 3) Cluster GKE Standard ─────────────────────────────────────────────────────
gcloud container clusters describe "$GKE_CLUSTER" --zone="$GCP_ZONE" >/dev/null 2>&1 || \
    gcloud container clusters create "$GKE_CLUSTER" \
        --zone="$GCP_ZONE" \
        --release-channel=regular \
        --num-nodes=1 \
        --machine-type=e2-small \
        --enable-ip-alias \
        --workload-pool="${GCP_PROJECT_ID}.svc.id.goog"

# 4) Node pool dedicado (privileged + hostNetwork OK em pool Standard) ──────
gcloud container node-pools describe "$NODE_POOL" --cluster="$GKE_CLUSTER" --zone="$GCP_ZONE" >/dev/null 2>&1 || \
    gcloud container node-pools create "$NODE_POOL" \
        --cluster="$GKE_CLUSTER" --zone="$GCP_ZONE" \
        --machine-type=e2-standard-2 \
        --num-nodes=1 \
        --image-type=COS_CONTAINERD \
        --node-taints=saferkids=true:NoSchedule \
        --node-labels=workload=saferkids

# 5) Service Account de deploy + WIF ────────────────────────────────────────
SA_EMAIL="${DEPLOY_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1 || \
    gcloud iam service-accounts create "$DEPLOY_SA_NAME" --display-name="GitHub Actions deployer"

for role in roles/artifactregistry.writer roles/container.developer roles/iam.serviceAccountTokenCreator; do
    gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
        --member="serviceAccount:${SA_EMAIL}" --role="$role" --condition=None >/dev/null
done

gcloud iam workload-identity-pools describe "$POOL_NAME" --location=global >/dev/null 2>&1 || \
    gcloud iam workload-identity-pools create "$POOL_NAME" --location=global --display-name="GitHub"

gcloud iam workload-identity-pools providers describe "$PROVIDER_NAME" \
    --location=global --workload-identity-pool="$POOL_NAME" >/dev/null 2>&1 || \
    gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_NAME" \
        --location=global --workload-identity-pool="$POOL_NAME" \
        --display-name="GitHub OIDC" \
        --issuer-uri="https://token.actions.githubusercontent.com" \
        --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
        --attribute-condition="assertion.repository=='${GH_REPO}'"

PROJECT_NUMBER="$(gcloud projects describe "$GCP_PROJECT_ID" --format='value(projectNumber)')"
WIF_PROVIDER="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_NAME}/providers/${PROVIDER_NAME}"
PRINCIPAL="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_NAME}/attribute.repository/${GH_REPO}"

gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
    --role=roles/iam.workloadIdentityUser \
    --member="$PRINCIPAL" >/dev/null

# 6) Firewall: AirPlay (TCP 7000/7100, UDP 6000-7100) e WireGuard (UDP 51820) ─
NETWORK_TAG="gke-${GKE_CLUSTER}"
gcloud compute firewall-rules describe saferkids-airplay >/dev/null 2>&1 || \
    gcloud compute firewall-rules create saferkids-airplay \
        --direction=INGRESS --action=ALLOW \
        --rules=tcp:7000,tcp:7100,udp:6000-7100,udp:51820 \
        --source-ranges=0.0.0.0/0 --target-tags="$NETWORK_TAG"

cat <<EOF

✅ Bootstrap concluído.

Configure como Variables (não Secrets) no GitHub → Settings → Secrets and variables → Actions:

  GCP_PROJECT_ID = ${GCP_PROJECT_ID}
  GCP_REGION     = ${GCP_REGION}
  GKE_CLUSTER    = ${GKE_CLUSTER}
  GKE_LOCATION   = ${GCP_ZONE}
  AR_REPOSITORY  = ${AR_REPOSITORY}
  WIF_PROVIDER   = ${WIF_PROVIDER}
  DEPLOY_SA      = ${SA_EMAIL}

E como Secret:

  SAFERKIDS_SECRET_JSON = {"WG_HOST":"vpn.example.com","WG_PASSWORD_HASH":"<bcrypt>","UXPLAY_NAME":"saferkids","SEGMENT_SECONDS":"600"}

EOF
