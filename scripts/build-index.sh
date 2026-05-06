#!/usr/bin/env bash
# Gera ./data/index.faiss e ./data/labels.bin a partir de resources/references.json.gz.
# Roda UMA VEZ por mudança no dataset. O Dockerfile.api runtime apenas copia esses
# artefatos do host — assim o `docker build` final é leve e rápido.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE_TAG="rinha-fraud-indexer:local"
CONTAINER_NAME="rinha-idx-extract-$$"

echo "[1/3] Building index-build stage..."
docker build --target index-build -t "$IMAGE_TAG" -f Dockerfile.api .

echo "[2/3] Extracting /data → ./data ..."
mkdir -p data
docker create --name "$CONTAINER_NAME" "$IMAGE_TAG" >/dev/null
trap 'docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT
docker cp "$CONTAINER_NAME:/data/index.faiss" ./data/index.faiss
docker cp "$CONTAINER_NAME:/data/labels.bin"  ./data/labels.bin

echo "[3/3] Done."
ls -lh data/index.faiss data/labels.bin
