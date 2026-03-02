
#!/usr/bin/env python3
import ssl
import socket
import json
import sys
import pwinput
import logging
import time

# ======= CONFIG =======
GATEWAY_IP = "10.0.0.3"
GATEWAY_PORT = 4443
SERVER_CN = "gateway.local"
CA_FILE = "/tmp/CA_workspace/ca.crt"
CLIENT_CERT = "/tmp/PDP_workspace/pdp.crt"
CLIENT_KEY = "/tmp/PDP_workspace/pdp.key"

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
            logging.warning(f"[!] TLS command failed: {e}. Retrying in {retry_delay}s...")
            time.sleep(retry_delay)

# ======= PUBLIC FUNCTIONS =======
def Generate_Wiregaurd(VPN_IP,Port):
    """Tell the Gateway to Generate the Wireguard keys"""

    return _send_tls_command({"action" : "Generate_keys","Address" : VPN_IP,"ListenPort":Port})

def Refresh_Gateway_Firewall():
    """Tells the Gateway to Refresh Firewall Rules"""
    return _send_tls_command({"action" : "Refresh_Rules"})

def add_peer(client_vpn_ip, client_pub_key):
    """Tell the Gateway to add the peer information"""

    return _send_tls_command({"action": "load_Peer", "public_key": client_pub_key, "Vpn_ip":client_vpn_ip})

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

def Start_Wireguard(Permission):
    return _send_tls_command({
        "action": Permission
    })



# ======= MAIN CLI HANDLER =======
if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.info("Usage:")
        logging.info("  python3 Gateway_SSL.py remove_peer <public_key>")
        logging.info("  python3 Gateway_SSL.py Start")
        logging.info("  python3 Gateway_SSL.py resync")
        logging.info("  python3 Gateway_SSL.py Request_Permission <ALLOW|DENY> <client_vpn_ip> <resource_ip> <port> <protocol>")
        sys.exit(1)


    action = sys.argv[1]
    if action == "remove_peer" and len(sys.argv) == 3:
        pubkey = sys.argv[2]
        logging.info(send_remove_peer(pubkey))
    elif action == "Start":
        logging.info(Start_Wireguard("Start"))
    elif action == "load_Peer":
        logging.info(add_peer())
    elif action == "resync":
        logging.info(send_resync())
    elif action == "Request_Permission":
        logging.info(Request_Permission())
    else:
        logging.info("Invalid usage.")
