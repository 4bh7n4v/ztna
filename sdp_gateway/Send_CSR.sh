#!/bin/bash
set -euo pipefail

# ================= CONFIG =================
CA_USER="kali"
CA_IP="192.168.43.129"
CA_PATH="/home/$CA_USER/Desktop/ztna/CA_Authority/gateway"

# Local folder containing the CSR
LOCAL_CERTS="$(pwd)/OpenSSL"

# CSR file argument
CSR_FILE="$1"

if [ -z "$CSR_FILE" ]; then
    echo "Usage: $0 <csr_file>"
    echo "Example: $0 gateway.csr"
    exit 1
fi

# Ensure CSR file exists
if [ ! -f "$LOCAL_CERTS/$CSR_FILE" ]; then
    echo "Error: CSR file '$LOCAL_CERTS/$CSR_FILE' not found."
    exit 2
fi

# ================= UPLOAD CSR =================
echo "[*] Sending CSR '$CSR_FILE' to CA..."
scp "$LOCAL_CERTS/$CSR_FILE" "$CA_USER@$CA_IP:$CA_PATH"

echo "[+] CSR sent successfully to $CA_USER@$CA_IP:$CA_PATH"
