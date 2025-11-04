
# #!/usr/bin/env python3
# import ssl
# import socket
# import json
# import sys

# # ======= CONFIG =======
# GATEWAY_IP = "192.168.43.130"          # Replace with your Gateway VM IP
# GATEWAY_PORT = 4443
# SERVER_CN = "gateway.local"                    # Must match CN in server certificate
# CA_FILE = "/home/uneedituh/ztna/sdp_controller/OpenSSL/ca.crt"
# CLIENT_CERT = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.crt"
# CLIENT_KEY = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.key"

# # ======= ARGUMENT CHECK =======
# if len(sys.argv) != 2:
#     print(f"Usage: python3 {sys.argv[0]} <public_key>")
#     sys.exit(1)

# public_key_input = sys.argv[1]

# # ======= SETUP SSL CONTEXT =======
# context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
# context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
# context.check_hostname = True
# context.verify_mode = ssl.CERT_REQUIRED

# # ======= CONNECT =======
# server_addr = (GATEWAY_IP, GATEWAY_PORT)
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# try:
#     tls_sock = context.wrap_socket(sock, server_hostname=SERVER_CN)
#     tls_sock.settimeout(10)  # 10s timeout
#     print(f"[*] Connecting to {GATEWAY_IP}:{GATEWAY_PORT}...")
#     tls_sock.connect(server_addr)
#     print("[*] TLS handshake successful.")
# except ssl.SSLError as e:
#     print("[!] TLS handshake failed:", e)
#     sys.exit(1)
# except socket.timeout:
#     print("[!] Connection timed out.")
#     sys.exit(1)
# except socket.error as e:
#     print("[!] Socket error:", e)
#     sys.exit(1)

# # ======= SEND COMMAND =======
# command = {
#     "action": "remove_peer",
#     "public_key": public_key_input
# }

# try:
#     tls_sock.send(json.dumps(command).encode())
# except Exception as e:
#     print("[!] Failed to send command:", e)
#     tls_sock.close()
#     sys.exit(1)

# # ======= RECEIVE RESPONSE =======
# try:
#     response = tls_sock.recv(4096).decode()
#     print("[*] Response from Gateway:", response)
# except Exception as e:
#     print("[!] Failed to receive response:", e)

# tls_sock.close()


#!/usr/bin/env python3
# import ssl
# import socket
# import json

# # ======= CONFIG =======
# GATEWAY_IP = "192.168.43.130"        # Replace with your Gateway VM IP
# GATEWAY_PORT = 4443
# SERVER_CN = "gateway.local"          # Must match CN in server certificate
# CA_FILE = "/home/uneedituh/ztna/sdp_controller/OpenSSL/ca.crt"
# CLIENT_CERT = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.crt"
# CLIENT_KEY = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.key"


# def send_command(command: dict) -> str:
#     """Send a JSON command to the Gateway over TLS and return response."""
#     context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
#     context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
#     context.check_hostname = True
#     context.verify_mode = ssl.CERT_REQUIRED

#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     try:
#         tls_sock = context.wrap_socket(sock, server_hostname=SERVER_CN)
#         tls_sock.settimeout(10)
#         print(f"[*] Connecting to {GATEWAY_IP}:{GATEWAY_PORT}...")
#         tls_sock.connect((GATEWAY_IP, GATEWAY_PORT))
#         print("[*] TLS handshake successful.")

#         tls_sock.send(json.dumps(command).encode())
#         response = tls_sock.recv(4096).decode()
#         print("[*] Response from Gateway:", response)
#         return response

#     except Exception as e:
#         print("[!] Communication error:", e)
#         return f"Error: {e}"
#     finally:
#         tls_sock.close()


# def send_remove_peer(public_key: str) -> str:
#     """Request the Gateway to remove a specific peer."""
#     command = {
#         "action": "remove_peer",
#         "public_key": public_key
#     }
#     return send_command(command)


# def send_resync() -> str:
#     """Request the Gateway to resync (strip + reload) WireGuard configuration."""
#     command = {
#         "action": "resync"
#     }
#     return send_command(command)


# # ===== Optional CLI Support =====
# if __name__ == "__main__":
#     import sys
#     if len(sys.argv) == 3 and sys.argv[1] == "remove_peer":
#         send_remove_peer(sys.argv[2])
#     elif len(sys.argv) == 2 and sys.argv[1] == "resync":
#         send_resync()
#     else:
#         print(f"Usage:\n  python3 {sys.argv[0]} remove_peer <public_key>\n  python3 {sys.argv[0]} resync")

#!/usr/bin/env python3
import ssl
import socket
import json
import sys

# ======= CONFIG =======
GATEWAY_IP = "192.168.43.130"
GATEWAY_PORT = 4443
SERVER_CN = "gateway.local"
CA_FILE = "/home/uneedituh/ztna/sdp_controller/OpenSSL/ca.crt"
CLIENT_CERT = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.crt"
CLIENT_KEY = "/home/uneedituh/ztna/sdp_controller/OpenSSL/controller.key"

# ======= COMMON FUNCTION =======
def _send_tls_command(command: dict) -> str:
    """Internal helper — sends JSON command to Gateway and returns response."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.create_connection((GATEWAY_IP, GATEWAY_PORT), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_CN) as tls_sock:
            tls_sock.send(json.dumps(command).encode())
            return tls_sock.recv(4096).decode()

# ======= PUBLIC FUNCTIONS =======
def send_remove_peer(public_key: str):
    """Tell the Gateway to remove a peer by public key."""
    return _send_tls_command({"action": "remove_peer", "public_key": public_key})

def send_resync():
    """Tell the Gateway to perform wg-quick strip + syncconf."""
    return _send_tls_command({"action": "resync"})

# ======= MAIN CLI HANDLER =======
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:\n  python3 Gateway_SSL.py send_remove_peer <public_key>\n  python3 Gateway_SSL.py send_resync")
        sys.exit(1)

    action = sys.argv[1]
    if action == "remove_peer" and len(sys.argv) == 3:
        pubkey = sys.argv[2]
        print(send_remove_peer(pubkey))
    elif action == "resync":
        print(send_resync())
    else:
        print("Invalid usage.")
