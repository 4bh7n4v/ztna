#!/bin/bash
set -e

echo "[*] Step 1: Update and install system-level packages..."
sudo apt update > /dev/null 2>&1
sudo apt install -y python3-pip python3-venv libffi-dev python3-dev build-essential wireguard > /dev/null 2>&1

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