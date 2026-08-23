#!/usr/bin/env bash
# Installer di GPMonitor (Docker). Uso: git clone <repo> gpmonitor && cd gpmonitor && ./install.sh
set -e
cd "$(cd "$(dirname "$0")" && pwd)/collector"

echo "==> Controllo Docker..."
if ! command -v docker >/dev/null 2>&1; then
  echo "    Docker non presente: lo installo da get.docker.com ..."
  curl -fsSL https://get.docker.com | sh
fi

echo "==> Chiave di monitoraggio (genero se assente)..."
mkdir -p ssh data
if [ ! -f ssh/monitor_ed25519 ]; then
  ssh-keygen -t ed25519 -N "" -f ssh/monitor_ed25519 -C "gpmon@$(hostname)"
fi

echo "==> Avvio GPMonitor (build + up)..."
docker compose up -d --build

echo
echo "FATTO. GPMonitor e' attivo."
echo "1) Modifica collector/docker-compose.yml -> MON_HOSTS (i tuoi server) e MON_BIND (indirizzo di ascolto)."
echo "2) Sui server da monitorare, installa la sonda a comando forzato con la chiave qui sotto (vedi README.md)."
echo "3) Applica:  cd collector && docker compose up -d"
echo
echo "Chiave PUBBLICA di monitoraggio da distribuire ai server:"
cat ssh/monitor_ed25519.pub
