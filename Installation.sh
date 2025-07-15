#!/bin/bash
set -e

echo "[*] Step 1: Update and install system-level packages..."
sudo apt update
sudo apt install -y python3-pip python3-venv libffi-dev python3-dev build-essential wireguard

echo "[*] Step 2: Create and activate virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Step 3: Install Python packages in venv..."
pip install -r requirements.txt

deactivate

echo "[*] Step 4: WireGuard Key Generation ... "
wg genkey | tee privatekey | wg pubkey > publickey
