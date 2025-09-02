#!/bin/bash
# Bash script to create a CA certificate and key

# Directory to store CA files
CA_DIR="./CA"
mkdir -p "$CA_DIR"

# CA private key and certificate
CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"

# Create CA private key
echo "Creating CA private key..."
openssl genrsa -out "$CA_KEY" 4096

# Create self-signed CA certificate
echo "Creating CA certificate..."
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" \
    -subj "/C=IN/ST=State/L=City/O=MyOrganization/OU=IT/CN=MyCA"

echo "CA created successfully!"
echo "CA Key: $CA_KEY"
echo "CA Cert: $CA_CERT"

# Optional: create function to generate a certificate signed by this CA
generate_cert() {
    NAME=$1
    DIR=$2
    mkdir -p "$DIR"
    KEY="$DIR/$NAME.key"
    CSR="$DIR/$NAME.csr"
    CRT="$DIR/$NAME.crt"

    # Generate private key
    openssl genrsa -out "$KEY" 2048

    # Generate CSR
    openssl req -new -key "$KEY" -out "$CSR" -subj "/C=IN/ST=State/L=City/O=MyOrganization/OU=IT/CN=$NAME"

    # Sign CSR with CA
    openssl x509 -req -in "$CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CRT" -days 365 -sha256

    echo "$NAME certificate created:"
    echo "Key: $KEY"
    echo "Cert: $CRT"
}

# Example usage: uncomment to generate certs
# generate_cert "Controller" "./Controller"
# generate_cert "Gateway" "./Gateway"
# generate_cert "User" "./User"
