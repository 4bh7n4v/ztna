import json
import ssl
import socket
import subprocess

WG_CONF_FILE = "/tmp/wireguard/wg0.conf"  # adjust if needed
WG_INTERFACE = "wg0"
LISTEN_PORT = 4443

def remove_peer(public_key):
    """
    Removes a WireGuard peer both from the live interface and the config file.
    """
    # 1️⃣ Remove from running interface
    try:
        subprocess.run(
            ["sudo", "wg", "set", WG_INTERFACE, "peer", public_key, "remove"],
            check=True
        )
    except subprocess.CalledProcessError:
        return False

    # 2️⃣ Remove from config file
    try:
        with open(WG_CONF_FILE, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return False

    new_lines = []
    peer_block = []
    skip = False

    for line in lines:
        if line.strip() == "[Peer]":
            if peer_block and not skip:
                new_lines.extend(peer_block)
            peer_block = [line]
            skip = False
            continue

        if line.startswith("PublicKey") and public_key in line:
            skip = True

        peer_block.append(line)

        if line.strip() == "":
            if not skip:
                new_lines.extend(peer_block)
            peer_block = []
            skip = False

    if peer_block and not skip:
        new_lines.extend(peer_block)

    with open(WG_CONF_FILE, "w") as f:
        f.writelines(new_lines)

    return True

def start_tls_server():
    """
    Starts a TLS server that listens for client commands.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="gateway.crt", keyfile="gateway.key")
    context.load_verify_locations(cafile="ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_sock = context.wrap_socket(sock, server_side=True)
    tls_sock.bind(("0.0.0.0", LISTEN_PORT))
    tls_sock.listen(5)
    print(f"Gateway TLS server listening on port {LISTEN_PORT}...")

    while True:
        try:
            conn, addr = tls_sock.accept()
            print(f"Connection from {addr}")
            data = conn.recv(4096)
            if not data:
                conn.close()
                continue

            try:
                command = json.loads(data.decode())
            except json.JSONDecodeError:
                conn.send(b"Invalid JSON")
                conn.close()
                continue

            if command.get("action") == "remove_peer":
                public_key = command.get("public_key")
                if not public_key:
                    conn.send(b"Missing public_key")
                else:
                    success = remove_peer(public_key)
                    conn.send(b"Peer removed" if success else b"Failed to remove peer")
            else:
                conn.send(b"Unknown action")

            conn.close()

        except Exception as e:
            print(f"Error handling connection: {e}")
            continue

if __name__ == "__main__":
    start_tls_server()
