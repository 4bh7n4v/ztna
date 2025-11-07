
#!/usr/bin/env python3
import ssl
import socket
import json
import sys
import pwinput
import time

# ======= CONFIG =======
GATEWAY_IP = "10.0.1.6"
GATEWAY_PORT = 4443
SERVER_CN = "gateway.local"
CA_FILE = "/home/uneedituh/ztna/sdp_controller/OpenSSL/ca.crt"
CLIENT_CERT = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.crt"
CLIENT_KEY = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.key"

# ======= COMMON FUNCTION =======
def _send_tls_command(command: dict, retry_delay=5) -> str:
    """
    Sends JSON command to Gateway over TLS.
    Retries until success with a delay between attempts.
    """
    # Prompt PEM passphrase once with masked input
    #pem_passphrase = pwinput.pwinput(prompt="Enter PEM passphrase: ", mask="*")
    pem_passphrase = "MyStrongPassword"

    while True:
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
            context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY, password=pem_passphrase)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((GATEWAY_IP, GATEWAY_PORT), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=SERVER_CN) as tls_sock:
                    tls_sock.send(json.dumps(command).encode())
                    response = tls_sock.recv(4096).decode()
                    return response  # Success! Exit loop

        except (ssl.SSLError, socket.error, ConnectionRefusedError) as e:
            print(f"[!] TLS command failed: {e}. Retrying in {retry_delay}s...")
            time.sleep(retry_delay)

# ======= PUBLIC FUNCTIONS =======
def send_remove_peer(public_key: str):
    """Tell the Gateway to remove a peer by public key."""
    return _send_tls_command({"action": "remove_peer", "public_key": public_key})

def send_resync():
    """Tell the Gateway to perform wg-quick strip + syncconf."""
    return _send_tls_command({"action": "resync"})

def Request_Permission(Permission,client_vpnip,resourceip,port,protocol):
    return _send_tls_command({
    "action": Permission,              
    "client_vpn_ip": client_vpnip,
    "resource_ip": resourceip,
    "ports": port,
    "protocol": protocol
})


# ======= MAIN CLI HANDLER =======
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:\n  python3 Gateway_SSL.py send_remove_peer <public_key>\n  python3 Gateway_SSL.py send_resync")
        print("export KEY_PASS=MyStrongPassword")
        sys.exit(1)

    action = sys.argv[1]
    if action == "remove_peer" and len(sys.argv) == 3:
        pubkey = sys.argv[2]
        print(send_remove_peer(pubkey))
    elif action == "resync":
        print(send_resync())
    elif action == "Request_Permission":
        print(Request_Permission())
    else:
        print("Invalid usage.")
