#!/bin/bash
set -e

# scripts/build-in-container.sh
# Reproducible build for K-Watch inside an Ubuntu 24.04 container.

IMAGE_NAME="kwatch-builder"
CONTAINER_NAME="kwatch-build-instance"

echo "[*] Building builder image (Ubuntu 24.04)..."
docker build -t $IMAGE_NAME -f - . <<EOF
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    linux-tools-common linux-tools-generic \
    pkg-config cmake ncurses-dev build-essential
WORKDIR /build
EOF

echo "[*] Running build in container..."
docker run --rm \
    -v $(pwd):/src \
    -v $(pwd)/build-container:/build \
    $IMAGE_NAME \
    bash -c "cmake /src && cmake --build ."

echo "[+] Build complete. Binary is at ./build-container/kwatch"
