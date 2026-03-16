#!/bin/bash
set -e

echo "[*] Step 1: Update and install system-level packages..."
sudo apt update > /dev/null 2>&1
sudo apt install -y python3-pip python3-venv libffi-dev python3-dev build-essential wireguard jq > /dev/null 2>&1

echo "[*] Step 2: Create and activate virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Step 3: Install Python packages in venv..."
while IFS= read -r package || [[ -n "$package" ]]; do
  [[ -z "$package" || "$package" =~ ^# ]] && continue

  if ! pip install "$package" > /dev/null 2>&1; then
    echo "Installation failed for package: $package"
    deactivate
    exit 1
  fi
done < requirements.txt


deactivate

echo "[*] Step 4: WireGuard Key Generation ... "
wg genkey | tee privatekey | wg pubkey > publickey

new_key=$(cat publickey)
jq 'map(if .gateway_id == "gw-01" then .wireguard_public_key = "'"$new_key"'" else . end)' \
  sdp_controller/sdp_gateway_details.json > temp.json && mv temp.json sdp_controller/sdp_gateway_details.json

echo "[*] Step 5: Update wg0.conf with new private key..."
WG_CONF_PATH="sdp_gateway/wg0.conf"
PRIVATE_KEY=$(cat privatekey)

if [[ -f "$WG_CONF_PATH" ]]; then
  sed -i "s|^PrivateKey = .*|PrivateKey = $PRIVATE_KEY|" "$WG_CONF_PATH"
  echo "Updated $WG_CONF_PATH with new private key."
else
  echo "Warning: $WG_CONF_PATH not found."
fi

