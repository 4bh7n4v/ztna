SHELL := /bin/bash

# -------------------------
# Configuration
# -------------------------
COMMON_DIR := ../Common
TEMPLATE_FILE := $(COMMON_DIR)/san_template.cnf
OPENSSL_DIR := ./OpenSSL
OUTPUT_DIR := $(OPENSSL_DIR)
COMMON_NAME := gateway.local
DNS_NAME := gateway.local
IP_ADDRESS := $(shell hostname -I | awk '{print $$1}')

# AES passphrase for private key (set as environment variable)
KEY_PASS ?= MySecretPassword

# CA information for reference (remote CA, no local signing)
CA_HOST := user@CA_HOST
CA_REMOTE_DIR := /path/to/CA/incoming/

# -------------------------
# Default target
# -------------------------
all: $(OUTPUT_DIR)/gateway.csr

# -------------------------
# 1️⃣ Generate SAN config
# -------------------------
$(OUTPUT_DIR)/san_gateway.cnf: $(TEMPLATE_FILE)
	@echo "[+] Generating SAN configuration for Gateway..."
	@mkdir -p $(OUTPUT_DIR)
	@sed "s/__COMMON_NAME__/$(COMMON_NAME)/; s/__DNS_NAME__/$(DNS_NAME)/; s/__IP_ADDRESS__/$(IP_ADDRESS)/" \
	$(TEMPLATE_FILE) > $@
	@echo "[✓] Created SAN file: $@"

# -------------------------
# 2️⃣ Generate AES-encrypted private key
# -------------------------
$(OUTPUT_DIR)/gateway.key:
	@echo "[+] Generating AES-256 encrypted Gateway private key..."
	@mkdir -p $(OUTPUT_DIR)
	@openssl genrsa -aes256 -passout env:KEY_PASS -out $@ 2048
	@echo "[✓] Created encrypted key: $@"

# -------------------------
# 3️⃣ Generate CSR
# -------------------------
$(OUTPUT_DIR)/gateway.csr: $(OUTPUT_DIR)/gateway.key $(OUTPUT_DIR)/san_gateway.cnf
	@echo "[+] Generating Gateway CSR..."
	@mkdir -p $(OUTPUT_DIR)
	@openssl req -new -key $< -passin env:KEY_PASS -out $@ \
	-subj "/C=IN/ST=Kerala/L=Amritapuri/O=MyOrg/OU=Gateway/CN=$(COMMON_NAME)" \
	-config $(OUTPUT_DIR)/san_gateway.cnf -extensions v3_req
	@echo "[✓] CSR created: $@"
	@echo "[→] Send this CSR to the CA for signing."

# -------------------------
# 4️⃣ Send CSR to remote CA
# -------------------------
Send2CA: $(OUTPUT_DIR)/gateway.csr
	@echo "[+] Sending Gateway CSR to remote CA..."
	@scp $< $(CA_HOST):$(CA_REMOTE_DIR)
	@echo "[→] CSR sent to remote CA at $(CA_HOST):$(CA_REMOTE_DIR)"
	@echo "[→] After signing, download the signed certificate to $(OUTPUT_DIR)/gateway.crt"

# -------------------------
# 5️⃣ Verify signed certificate
# -------------------------
verify: $(OUTPUT_DIR)/gateway.crt
	@echo "[+] Verifying Gateway certificate..."
	@openssl x509 -in $< -noout -text | grep -E "Subject:|Issuer:|DNS:|IP Address:"
	@echo "[✓] Verification complete."

# -------------------------
# 6️⃣ Clean generated files
# -------------------------
clean:
	@echo "[!] Cleaning Gateway OpenSSL files..."
	@rm -f $(OUTPUT_DIR)/*.key $(OUTPUT_DIR)/*.csr $(OUTPUT_DIR)/*.cnf $(OUTPUT_DIR)/*.crt $(OUTPUT_DIR)/*.srl
	@echo "[✓] Cleanup complete."

# -------------------------
# 7️⃣ Help target
# -------------------------
help:
	@echo "Available Makefile targets for Gateway:"
	@echo "----------------------------------------------------"
	@echo "  make all       -> Generate SAN, AES-encrypted key + CSR"
	@echo "  make Send2CA    -> Send CSR to remote CA"
	@echo "  make verify    -> Verify signed certificate (.crt)"
	@echo "  make clean     -> Remove all generated files"
	@echo "  make help      -> Show this help message"
	@echo ""
	@echo "Environment variable:"
	@echo "  KEY_PASS       -> Passphrase for AES-encrypted private key"
	@echo "                   Example:"
	@echo "                     export KEY_PASS=MyStrongPassword"
	@echo "----------------------------------------------------"
