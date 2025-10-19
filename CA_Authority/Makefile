SHELL := /bin/bash

# -------------------------
# Configuration
# -------------------------
OUTPUT_DIR := ./CA
CA_KEY := $(OUTPUT_DIR)/ca.key
CA_CERT := $(OUTPUT_DIR)/ca.crt
CA_SERIAL := $(OUTPUT_DIR)/ca.srl
DAYS_VALID := 3650   # CA certificate validity (10 years)
KEY_PASS ?= MyCAPassword  # Optional passphrase for CA key

# -------------------------
# Default target
# -------------------------
all: check_ca

# -------------------------
# 1 Check if CA key and cert exist
# -------------------------
check_ca:
	@if [ -f "$(CA_KEY)" ] && [ -f "$(CA_CERT)" ]; then \
		echo "[✓] CA key and certificate already exist. Ready to sign client CSRs."; \
	else \
		echo "[!] CA key or certificate not found. Creating new CA..."; \
		$(MAKE) create_ca; \
	fi

# -------------------------
# 2 Create new CA (key + certificate)
# -------------------------
create_ca:
	@echo "[+] Creating CA directory..."
	@mkdir -p $(OUTPUT_DIR)
	@echo "[+] Generating AES-256 encrypted CA private key..."
	@openssl genrsa -aes256 -passout env:KEY_PASS -out $(CA_KEY) 4096
	@echo "[✓] CA private key created: $(CA_KEY)"
	@echo "[+] Generating self-signed CA certificate..."
	@openssl req -x509 -new -nodes -key $(CA_KEY) -sha256 -days $(DAYS_VALID) \
		-out $(CA_CERT) -passin env:KEY_PASS \
		-subj "/C=IN/ST=Kerala/L=Amritapuri/O=MyOrg/OU=CA/CN=MyRootCA"
	@echo "[✓] CA certificate created: $(CA_CERT)"
	@echo "[→] Ready to sign client CSRs."

# -------------------------
# 3 Fully automatic sign client CSRs and clean CSR files
# -------------------------
sign: check_ca
	@echo "[*] Signing all client CSRs..."
	@for csr in controller/*.csr gateway/*.csr; do \
		if [ -f "$$csr" ]; then \
			OUTPUT_CRT="$(OUTPUT_DIR)/$$(basename $$csr .csr).crt"; \
			echo "[+] Signing $$csr..."; \
			openssl x509 -req -in $$csr -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial \
				-out $$OUTPUT_CRT -days 365 -sha256 -passin env:KEY_PASS; \
			echo "[✓] Signed certificate saved at $$OUTPUT_CRT"; \
			echo "[*] Removing CSR $$csr..."; \
			rm -f $$csr; \
		else \
			echo "[!] No CSRs found in controller/ or gateway/"; \
		fi \
	done

# -------------------------
# 4 Verify a certificate
# -------------------------
verify:
	@read -p "Enter path to certificate to verify: " CRT_FILE; \
	echo "[+] Verifying certificate $$CRT_FILE..."; \
	openssl verify -CAfile $(CA_CERT) $$CRT_FILE

# -------------------------
# 5 Clean generated CA files
# -------------------------
clean:
	@echo "[!] Cleaning CA directory..."
	@rm -f $(OUTPUT_DIR)/*.key $(OUTPUT_DIR)/*.crt $(OUTPUT_DIR)/*.srl
	@echo "[✓] CA files cleaned."

# -------------------------
# 6 Help target
# -------------------------
help:
	@echo "Available Makefile targets for CA Authority:"
	@echo "----------------------------------------------------"
	@echo "  make all       -> Check CA key/cert, create if missing"
	@echo "  make create_ca -> Force creation of CA key + self-signed cert"
	@echo "  make sign      -> Automatically sign all client CSRs in controller/ and gateway/ and delete CSRs"
	@echo "  make verify    -> Verify a certificate against the CA"
	@echo "  make clean     -> Remove all CA files"
	@echo "  make help      -> Show this help message"
	@echo ""
	@echo "Environment variable:"
	@echo "  KEY_PASS       -> Passphrase for AES-encrypted CA key"
	@echo "                   Example:"
	@echo "                     export KEY_PASS=MyCAPassword"
	@echo "----------------------------------------------------"
