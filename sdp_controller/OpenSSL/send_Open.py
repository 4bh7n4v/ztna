import ssl
import socket
import json
import sys

if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <public_key>")
    sys.exit(1)

# CLI input
public_key_input = sys.argv[1]

# Load CA and client certificates
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="/home/uneedituh/Controller/ca.crt")
context.load_cert_chain(certfile="/home/uneedituh/Controller/controller.crt", keyfile="/home/uneedituh/Controller/controller.key")

# Connect to Gateway/Seed by IP
server_addr = ("gateway.local", 4443)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap socket with TLS
tls_sock = context.wrap_socket(sock, server_hostname="gateway.local")  # Must match SAN IP
tls_sock.connect(server_addr)

# Use CLI input for public_key
command = {
    "action": "remove_peer",
    "public_key": public_key_input
}

# Send command
tls_sock.send(json.dumps(command).encode())

# Receive response
response = tls_sock.recv(4096).decode()
print(response)

tls_sock.close()
