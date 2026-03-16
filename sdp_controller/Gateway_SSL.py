#!/usr/bin/env python3
import ssl
import socket
import json
import sys
import logging
import time

# ======= CONFIG =======
GATEWAY_IP   = "10.0.2.254"    # SDPGateway-eth0 via S2
GATEWAY_PORT = 4433             # matches PORT_MTLS
SERVER_CN    = "gateway.zt"     # matches CN in PEP.cnf

CA_FILE     = "/tmp/CA_workspace/ca.crt"
CLIENT_CERT = "/tmp/Controller_workspace/PDP.crt"
CLIENT_KEY  = "/tmp/Controller_workspace/PDP.key"


# ======= COMMON FUNCTION =======
def _send_tls_command(command: dict, retry_delay=5) -> str:
    while True:
        try:
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(
                certfile=CLIENT_CERT,
                keyfile=CLIENT_KEY,
                password=None)
            context.check_hostname = False
            context.verify_mode    = ssl.CERT_REQUIRED

            with socket.create_connection((GATEWAY_IP, GATEWAY_PORT), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=SERVER_CN) as tls_sock:
                    tls_sock.send(json.dumps(command).encode())
                    
                    # ── Fix is here ──────────────────────────
                    data = tls_sock.recv(4096)
                    
                    if not data:
                        logging.warning('[!] Empty response from Gateway')
                        break
                    
                    try:
                        response = data.decode('utf-8')
                        logging.info('[TLS] Response: %s', response)
                        return response
                    except UnicodeDecodeError as e:
                        logging.error('[!] Bad response bytes: %s | raw: %s', e, data[:20])
                        break
                    # ─────────────────────────────────────────

        except (ssl.SSLError, socket.error, ConnectionRefusedError) as e:
            logging.warning('[!] TLS command failed: %s. Retrying in %ds...', e, retry_delay)
            time.sleep(retry_delay)


# ======= PUBLIC FUNCTIONS =======
def Generate_Wireguard(vpn_ip, port):
    """Tell the Gateway to generate WireGuard keys."""
    return _send_tls_command({
        "action"    : "Generate_keys",
        "Address"   : vpn_ip,
        "ListenPort": port
    })

def Refresh_Gateway_Firewall():
    """Tell the Gateway to refresh firewall rules."""
    return _send_tls_command({"action": "Refresh_Rules"})

def add_peer(client_vpn_ip, client_pub_key):
    """Tell the Gateway to add a WireGuard peer."""
    return _send_tls_command({
        "action"    : "load_Peer",
        "public_key": client_pub_key,
        "Vpn_ip"    : client_vpn_ip
    })

def send_remove_peer(public_key: str):
    """Tell the Gateway to remove a peer by public key."""
    return _send_tls_command({
        "action"    : "remove_peer",
        "public_key": public_key
    })

def send_resync():
    """Tell the Gateway to perform wg-quick strip + syncconf."""
    return _send_tls_command({"action": "resync"})

def Request_Permission(permission, client_vpnip, resourceip, port, protocol):
    """Request ALLOW or DENY for a client."""
    return _send_tls_command({
        "action"        : permission,
        "client_vpn_ip" : client_vpnip,
        "resource_ip"   : resourceip,
        "ports"         : port,
        "protocol"      : protocol
    })

def Start_Wireguard(permission):
    """Start WireGuard on Gateway."""
    return _send_tls_command({"action": permission})


# ======= MAIN CLI HANDLER =======
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 Gateway_SSL.py remove_peer <public_key>")
        print("  python3 Gateway_SSL.py Start")
        print("  python3 Gateway_SSL.py resync")
        print("  python3 Gateway_SSL.py load_Peer <vpn_ip> <public_key>")
        print("  python3 Gateway_SSL.py Request_Permission <ALLOW|DENY> <client_vpn_ip> <resource_ip> <port> <protocol>")
        sys.exit(1)

    action = sys.argv[1]

    if action == "remove_peer" and len(sys.argv) == 3:
        logging.info(send_remove_peer(sys.argv[2]))

    elif action == "Start":
        logging.info(Start_Wireguard("Start"))

    elif action == "load_Peer" and len(sys.argv) == 4:
        logging.info(add_peer(sys.argv[2], sys.argv[3]))

    elif action == "resync":
        logging.info(send_resync())

    elif action == "Request_Permission" and len(sys.argv) == 7:
        logging.info(Request_Permission(
            sys.argv[2],  # ALLOW or DENY
            sys.argv[3],  # client_vpn_ip
            sys.argv[4],  # resource_ip
            sys.argv[5],  # port
            sys.argv[6]   # protocol
        ))

    else:
        print("[!] Invalid usage or missing arguments.")
        sys.exit(1)