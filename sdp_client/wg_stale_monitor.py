#!/usr/bin/env python3
import subprocess
import logging
import argparse
import sys
import time
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


def get_latest_handshake(interface):
    """Returns the latest handshake time (epoch seconds) for the first peer."""
    try:
        result = subprocess.run(
            ["sudo", "wg", "show", interface, "dump"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode != 0:
            return None

        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            return None

        peer_info = lines[1].split("\t")
        latest = int(peer_info[4]) if peer_info[4].isdigit() else 0
        return latest if latest > 0 else None

    except Exception:
        return None


def monitor(interface, timeout):
    logging.info(f"[+] Monitoring WireGuard '{interface}' for stale handshake (> {timeout}s)")

    while True:
        latest = get_latest_handshake(interface)
        now = int(time.time())

        if latest is None:
            logging.warning(f"[!] No active peer or interface missing — stopping monitor.")
            break

        diff = now - latest
        logging.info(f"[monitor] Handshake age: {diff}s")

        if diff > timeout:
            logging.warning(f"[!] Stale handshake detected (> {timeout}s). Bringing interface down.")

            config_path = f"/tmp/CA_workspace/{interface}.conf"
            result = subprocess.run(
                ["wg-quick", "down", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            if result.returncode == 0:
                logging.info(f"[+] Interface '{interface}' successfully stopped.")
            else:
                logging.warning(f"[!] Failed to stop interface:\n{result.stderr}")

            break   # ← IMPORTANT

        time.sleep(60)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: wg_stale_monitor.py <interface> <timeout_seconds> [-v]")
        sys.exit(1)

    interface = sys.argv[1]
    timeout = int(sys.argv[2])

    # Check if -v is present anywhere in arguments
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    # Set logging level based on verbose
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    monitor(interface, timeout)