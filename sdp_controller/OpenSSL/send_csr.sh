#!/bin/bash

# ========== CONFIG ==========
CA_USER="kali"
CA_IP="192.168.181.17"
CA_PATH="/home/$CA_USER/CA"

LOCAL_CERTS="$HOME/Controller"
CSR_FILE="$1"

if [ -z "$CSR_FILE" ]; then
    echo "Usage: $0 <csr_file>"
    exit 1
fi

# Upload CSR to CA
echo "[*] Sending $CSR_FILE to CA..."
scp "$LOCAL_CERTS/$CSR_FILE" "$CA_USER@$CA_IP:$CA_PATH"

# Download signed cert back
SIGNED_CERT="${CSR_FILE%.csr}.crt"
echo "[*] Waiting for $SIGNED_CERT from CA..."
scp "$CA_USER@$CA_IP:$CA_PATH/$SIGNED_CERT" "$LOCAL_CERTS/"

# Download CA root cert
echo "[*] Downloading CA root certificate..."
scp "$CA_USER@$CA_IP:$CA_PATH/ca.crt" "$LOCAL_CERTS/"

echo "[+] Done. Certificates are in $LOCAL_CERTS/"
