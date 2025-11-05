#!/usr/bin/env python3
import subprocess
import sys
import time
import os

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
    print(f"[+] Monitoring WireGuard '{interface}' for stale handshake (> {timeout}s)")
    while True:
        latest = get_latest_handshake(interface)
        now = int(time.time())

        if latest is None:
            print(f"[!] No active peer or {interface} missing — stopping monitor.")
            break

        diff = now - latest
        print(f"[monitor] Handshake age: {diff}s")

        if diff > timeout:
            config_path = f"/tmp/{interface}.conf"
            print(f"[!] Stale handshake detected (> {timeout}s). Stopping interface and deleting config.")
            result = subprocess.run(
                ["sudo", "wg-quick", "down", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )


            if result.returncode == 0:
                if os.path.exists(config_path):
                    try:
                        os.remove(config_path)
                        print(f"[+] Configuration file '{config_path}' deleted.")
                    except Exception as e:
                        print(f"[!] Failed to delete config file: {e}")
                else:
                    print(f"[!] Config file '{config_path}' not found.")
            else:
                print(f"[!] Failed to bring down WireGuard interface '{config_path}'. Skipping deletion.")
                print(result.stderr.decode()) 

        time.sleep(60) 


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: wg_stale_monitor.py <interface> <timeout_seconds>")
        sys.exit(1)

    interface = sys.argv[1]
    timeout = int(sys.argv[2])
    monitor(interface, timeout)
