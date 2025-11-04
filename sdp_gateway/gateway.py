import json
import ssl
import socket
import subprocess

WG_CONF_FILE = "/tmp/wireguard/wg0.conf"  
RUNTIME_CONF = "/tmp/wireguard/runtime.conf"

def strip_and_resync():
    """
    Strips wg-quick-specific fields from WG_CONF_FILE and resyncs
    the configuration to the running WireGuard interface (wg0).
    """
    try:
        # Step 1: Strip wg-quick-specific fields
        subprocess.run(
            f"wg-quick strip {WG_CONF_FILE} | tee {RUNTIME_CONF} > /dev/null",
            shell=True,
            check=True
        )

        # Step 2: Apply runtime config live
        subprocess.run(
            ["wg", "syncconf", "wg0", RUNTIME_CONF],
            check=True
        )

        print("[*] WireGuard configuration successfully stripped and synced.")
        return True

    except subprocess.CalledProcessError as e:
        print("[!] Failed to strip or sync configuration:", e)
        return False

def remove_peer(public_key):
    """Remove a peer from the WireGuard config file. Returns True if removed."""
    try:
        with open(WG_CONF_FILE, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return False

    new_lines = []
    peer_block = []
    skip_block = False
    peer_found = False

    for line in lines:
        if line.strip() == "[Peer]":
            if peer_block:
                if not skip_block:
                    new_lines.extend(peer_block)
            peer_block = [line]
            skip_block = False
            continue

        peer_block.append(line)

        # Match PublicKey line ignoring spaces
        if line.strip().replace(" ", "").startswith("PublicKey=") and public_key in line:
            skip_block = True
            peer_found = True

    # Flush last block
    if peer_block and not skip_block:
        new_lines.extend(peer_block)

    # Write updated config
    with open(WG_CONF_FILE, "w") as f:
        f.writelines(new_lines)

    if peer_found:
        strip_and_resync()

        return peer_found

# ===== TLS Server Setup =====
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="./OpenSSL/gateway.crt", keyfile="./OpenSSL/gateway.key")
context.load_verify_locations(cafile="./OpenSSL/ca.crt")
context.verify_mode = ssl.CERT_REQUIRED

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tls_sock = context.wrap_socket(sock, server_side=True)
tls_sock.bind(("0.0.0.0", 4443))
tls_sock.listen(5)

print("[*] Gateway server listening on port 4443...")

try:
    while True:
        conn, addr = tls_sock.accept()
        print(f"[*] Connection from {addr}")
        try:
            data = conn.recv(4096)
            command = json.loads(data.decode())

            if command.get("action") == "remove_peer":
                success = remove_peer(command["public_key"])
                if success:
                    conn.send(b"Peer removed")
                    print(f"[+] Removed peer {command['public_key']}")
                else:
                    conn.send(b"Peer not found")
                    print(f"[-] Peer {command['public_key']} not found")
            
            elif command.get("action") == "resync":
                success = strip_and_resync()
                if success:
                    conn.send(b"WireGuard configuration resynced successfully")
                    print("[*] WireGuard configuration resynced successfully.")
                else:
                    conn.send(b"Failed to resync configuration")
                    print("[!] Failed to resync WireGuard configuration.")

            else:
                conn.send(b"Unknown action")
        except Exception as e:
            print("[!] Error handling client:", e)
        finally:
            conn.close()
except KeyboardInterrupt:
    print("\n[*] Server shutting down.")
    tls_sock.close()
