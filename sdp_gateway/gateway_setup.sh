#!/bin/bash
set -e

CA_DIR=~/CA   # Place where you copied ca.crt from CA
GATEWAY_IP="192.168.233.247"  # Replace with actual Gateway IP

mkdir -p ~/Gateway
cd ~/Gateway

# Generate private key
openssl genrsa -out gateway.key 2048

# Create SAN config
cat > san_gateway.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = v3_req
distinguished_name = dn

[ dn ]
C  = IN
ST = Kerala
L  = Amritapuri
O  = MyOrg
OU = Gateway
CN = gateway.local

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1   = gateway.local
IP.1    = ${GATEWAY_IP}
EOF

# CSR
openssl req -new -key gateway.key -out gateway.csr -config san_gateway.cnf

# Copy CSR to CA manually or via scp
echo "[+] Gateway CSR ready: ~/Gateway/gateway.csr (send this to CA for signing)"
