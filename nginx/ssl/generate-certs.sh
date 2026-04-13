#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# Generate self-signed TLS certificates for the Zero Trust lab
# ═══════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${SCRIPT_DIR}"

echo "══════════════════════════════════════════════"
echo "  Generating self-signed TLS certificate..."
echo "══════════════════════════════════════════════"

# Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -subj "/C=US/ST=Lab/L=ZeroTrust/O=ZeroTrustLab/OU=Security/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 644 "${CERT_DIR}/server.crt"
chmod 600 "${CERT_DIR}/server.key"

echo "══════════════════════════════════════════════"
echo "  ✅  Certificate generated successfully"
echo "  📄  Certificate: ${CERT_DIR}/server.crt"
echo "  🔑  Private key: ${CERT_DIR}/server.key"
echo "══════════════════════════════════════════════"
