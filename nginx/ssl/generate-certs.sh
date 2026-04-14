#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SSL_DIR="$SCRIPT_DIR"

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

mkdir -p "$SSL_DIR"

echo "Generating self-signed TLS certificate..."

openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout "$SSL_DIR/server.key" \
  -out "$SSL_DIR/server.crt" \
  -subj "/C=US/ST=Lab/L=ZeroTrust/O=ZeroTrustLab/OU=Security/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$SSL_DIR/server.key" || true
chmod 644 "$SSL_DIR/server.crt" || true
