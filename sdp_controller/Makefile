SHELL := /bin/bash

# -------------------------
# Configuration
# -------------------------
COMMON_DIR := ../Common
TEMPLATE_FILE := $(COMMON_DIR)/san_template.cnf
OPENSSL_DIR := ./OpenSSL
OUTPUT_DIR := $(OPENSSL_DIR)
COMMON_NAME := controller.local
DNS_NAME := controller.local
IP_ADDRESS := $(shell hostname -I | awk '{print $$1}')

# AES passphrase for private key (set as environment variable)
KEY_PASS ?= MySecretPassword

# Remote CA info (change these to your CA machine)
CA_USER := kali
CA_IP := 10.0.1.3
CA_HOST := $(CA_USER)@$(CA_IP)
CA_REMOTE_DIR := /home/$(CA_USER)/Desktop/ztna/CA_Authority/controller
CA_ROOT_PATH := ~/Desktop/ztna/CA_Authority/CA/ca.crt

# -------------------------
# Default target
# -------------------------
all: $(OUTPUT_DIR)/controller.csr

# -------------------------
# 1️⃣ Generate SAN config
# -------------------------
$(OUTPUT_DIR)/san_controller.cnf: $(TEMPLATE_FILE)
	@echo "[+] Generating SAN configuration for Controller..."
	@mkdir -p $(OUTPUT_DIR)
	@sed "s/__COMMON_NAME__/$(COMMON_NAME)/; s/__DNS_NAME__/$(DNS_NAME)/; s/__IP_ADDRESS__/$(IP_ADDRESS)/" \
	$(TEMPLATE_FILE) > $@
	@echo "[✓] Created SAN file: $@"

# -------------------------
# 2️⃣ Generate AES-encrypted private key
# -------------------------
$(OUTPUT_DIR)/controller.key:
	@echo "[+] Generating AES-256 encrypted Controller private key..."
	@mkdir -p $(OUTPUT_DIR)
	@openssl genrsa -aes256 -passout env:KEY_PASS -out $@ 2048
	@echo "[✓] Created encrypted key: $@"

# -------------------------
# 3️⃣ Generate CSR
# -------------------------
$(OUTPUT_DIR)/controller.csr: $(OUTPUT_DIR)/controller.key $(OUTPUT_DIR)/san_controller.cnf
	@echo "[+] Generating Controller CSR..."
	@openssl req -new -key $< -passin env:KEY_PASS -out $@ \
	-subj "/C=IN/ST=Telangana/L=Hyderabad/O=MyOrg/OU=Controller/CN=$(COMMON_NAME)" \
	-config $(OUTPUT_DIR)/san_controller.cnf -extensions v3_req
	@echo "[✓] CSR created: $@"
	@echo "[→] Use 'make Send2CA' to send this CSR to the CA for signing."

# -------------------------
# 4️⃣ Send CSR to remote CA
# -------------------------
Send2CA: $(OUTPUT_DIR)/controller.csr
	@echo "[+] Sending Controller CSR to remote CA..."
	@scp $< $(CA_HOST):$(CA_REMOTE_DIR)
	@echo "[✓] CSR successfully sent to remote CA."
	@echo "[→] Ask CA admin to run 'make sign-all' on CA Authority."

# -------------------------
# 5️⃣ Download signed certificate and CA root
# -------------------------
# FetchCerts:
# 	@echo "[+] Downloading signed certificate and CA root from CA Authority..."
# 	@scp $(CA_HOST):$(CA_PATH)/controller.crt $(OUTPUT_DIR)/controller.crt || echo "[!] controller.crt not found on CA yet."
# 	@scp $(CA_HOST):$(CA_ROOT_PATH) $(OUTPUT_DIR)/ca.crt || echo "[!] ca.crt not found on CA yet."
# 	@echo "[✓] Files downloaded to $(OUTPUT_DIR)."

# -------------------------
# 6️⃣ Verify signed certificate
# -------------------------
verify: $(OUTPUT_DIR)/controller.crt
	@echo "[+] Verifying Controller certificate..."
	@openssl x509 -in $< -noout -text | grep -E "Subject:|Issuer:|DNS:|IP Address:"
	@echo "[✓] Verification complete."

# -------------------------
# 7️⃣ Clean generated files
# -------------------------
clean:
	@echo "[!] Cleaning Controller OpenSSL files..."
	@rm -f $(OUTPUT_DIR)/*.key $(OUTPUT_DIR)/*.csr $(OUTPUT_DIR)/*.cnf $(OUTPUT_DIR)/*.crt $(OUTPUT_DIR)/*.srl
	@echo "[✓] Cleanup complete."

# -------------------------
# 8️⃣ Help menu
# -------------------------
help:
	@echo "Available Makefile targets for Controller:"
	@echo "----------------------------------------------------"
	@echo "  make all         -> Generate SAN, AES-encrypted key, and CSR"
	@echo "  make Send2CA     -> Send CSR to remote CA machine"
#	@echo "  make FetchCerts  -> Fetch signed cert + CA root from CA"
	@echo "  make verify      -> Verify signed certificate details"
	@echo "  make clean       -> Remove all generated OpenSSL files"
	@echo ""
	@echo "Environment variable:"
	@echo "  KEY_PASS         -> Passphrase for AES-encrypted private key"
	@echo "                     Example: export KEY_PASS=MyStrongPassword"
	@echo ""
	@echo "CA configuration:"
	@echo "  CA_HOST          -> $(CA_HOST)"
	@echo "  CA_PATH          -> $(CA_PATH)"
	@echo "----------------------------------------------------"
