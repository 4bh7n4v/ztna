#!/usr/bin/env bash
set -euo pipefail

# ================= CONFIG =================
CA_DIR="$HOME/Desktop/ztna/CA_Authority"
CA_CERT="$CA_DIR/CA/ca.crt"
CLIENTS_JSON="$CA_DIR/Clients.json"

# SSH options
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"

# Sanity checks
[ ! -f "$CA_CERT" ] && { echo "Error: CA cert '$CA_CERT' not found." >&2; exit 1; }
[ ! -f "$CLIENTS_JSON" ] && { echo "Error: Clients JSON '$CLIENTS_JSON' not found." >&2; exit 1; }

# Check for jq
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: 'jq' is required to parse JSON. Install it with: sudo apt install jq"
    exit 2
fi

# Load client entries
mapfile -t CLIENT_ENTRIES < <(jq -c '.[]' "$CLIENTS_JSON")

echo "[*] Sending signed certificates to clients listed in '$CLIENTS_JSON'."
echo

total=0
succeeded=0
skipped=0

for client_json in "${CLIENT_ENTRIES[@]}"; do
    total=$((total+1))

    NAME=$(echo "$client_json" | jq -r '.name // empty')
    IP=$(echo "$client_json" | jq -r '.ip // empty')
    USER=$(echo "$client_json" | jq -r '.user // empty')
    ROLE=$(echo "$client_json" | jq -r '.role // empty')
    REMOTE_DIR_TEMPLATE=$(echo "$client_json" | jq -r '.remote_dir // "/home/{user}/certs"')
    SSH_PORT=$(echo "$client_json" | jq -r '.ssh_port // 22')

    if [ -z "$NAME" ] || [ -z "$USER" ] || [ -z "$IP" ]; then
        echo "[!] Skipping malformed entry #$total"
        skipped=$((skipped+1))
        continue
    fi

    # Expand placeholders
    REMOTE_DIR="${REMOTE_DIR_TEMPLATE//\{user\}/$USER}"
    REMOTE_DIR="${REMOTE_DIR//\{role\}/$ROLE}"

    # Pick certificate by role
    CERT_FILE="$CA_DIR/CA/$ROLE.crt"
    if [ ! -f "$CERT_FILE" ]; then
        echo "[!] ($total) Signed certificate for role '$ROLE' not found at '$CERT_FILE'. Skipping."
        skipped=$((skipped+1))
        continue
    fi

    echo "[*] ($total) Sending '$CERT_FILE' + '$CA_CERT' to ${USER}@${IP}:${REMOTE_DIR} (port $SSH_PORT)..."

    # SCP both files in a single command
    if scp -P "$SSH_PORT" "$CERT_FILE" "$CA_CERT" "$USER@$IP:$REMOTE_DIR/"; then
        echo "    -> OK"
        succeeded=$((succeeded+1))
    else
        echo "    -> ERROR: SCP failed for $IP"
        skipped=$((skipped+1))
    fi
done

# Summary
echo
echo "Summary:"
echo "  Total entries processed : $total"
echo "  Successfully delivered  : $succeeded"
echo "  Skipped                 : $skipped"

exit 0
