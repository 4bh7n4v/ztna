#!/bin/bash

# ========== CONFIG ==========
CA_DIR="$HOME/CA"
CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"

CSR_FILE="$1"

if [ -z "$CSR_FILE" ]; then
    echo "Usage: $0 <csr_file>"
    exit 1
fi

BASENAME=$(basename "$CSR_FILE" .csr)
SIGNED_CERT="$CA_DIR/$BASENAME.crt"

echo "[*] Signing CSR: $CSR_FILE"
openssl x509 -req -in "$CA_DIR/$CSR_FILE" -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAcreateserial -out "$SIGNED_CERT" -days 365 -sha256

echo "[+] Signed cert created: $SIGNED_CERT"
