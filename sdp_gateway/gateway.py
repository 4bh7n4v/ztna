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

import subprocess

def allow_access(client_ip,resource_ip,port,proto):
    """
        sudo iptables -I FORWARD 1 -s <CLIENTVPNIP> -d <RESOURCEIP> -p tcp --dport <PORTBUMBER> -j ACCEPT
        sudo iptables -A FORWARD -d <CLIENTVPNIP> -s <RESOURCEIP> -m state --state RELATED,ESTABLISHED -j ACCEPT

    """

    try:
        # 2. ALLOW specific port (insert at top)
        subprocess.run([
            "iptables", "-I", "FORWARD", "1",
            "-s", client_ip,
            "-d", resource_ip,
            "-p", proto,
            "-m" , "multiport",
            "--dports", str(port),
            "-j", "ACCEPT"
        ], check=True)
        print(f"[OK] ACCEPT rule added for port {port}: {client_ip} -> {resource_ip}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to add ACCEPT {port} rule: {e}")

    try:
        # 1. DROP all traffic from client -> resource
        subprocess.run([
            "iptables", "-I", "FORWARD" , "2",
            "-s", client_ip,
            "-d", resource_ip,
            "-j", "DROP"
        ], check=True)
        print(f"[OK] DROP rule added: {client_ip} -> {resource_ip}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to add DROP rule: {e}")


    try:
        # 3. Allow return traffic (RESOURCE -> CLIENT)
        subprocess.run([
            "iptables", "-I", "FORWARD", "3",
            "-d", client_ip,
            "-s", resource_ip,
            "-m", "state",
            "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ], check=True)
        print(f"[OK] Return traffic rule added: {resource_ip} -> {client_ip}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to add return traffic rule: {e}")




def deny_access(client_ip,resource_ip,port,proto):
    # Insert rule for traffic from client to resource
    """
        sudo iptables -D FORWARD -s 10.0.0.1 -d resource.local -p tcp --dport 22 -j ACCEPT 
    """
    resource_ip = socket.gethostbyname(resource_ip)

    # 3. Delete return traffic rule
    try:
        subprocess.run([
            "iptables", "-D", "FORWARD",
            "-d", client_ip,
            "-s", resource_ip,
            "-m", "state",
            "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ], check=True)

        print(f"[OK] Deleted return traffic rule: {resource_ip} -> {client_ip}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Could not delete return traffic rule: {e}")


    # 2. Delete DROP rule (optional)
    try:
        subprocess.run([
            "iptables", "-D", "FORWARD",
            "-s", client_ip,
            "-d", resource_ip,
            "-j", "DROP"
        ], check=True)

        print(f"[OK] Deleted DROP rule: {client_ip} -> {resource_ip}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Could not delete DROP rule: {e}")



    # 1. Delete the Certain port Communincation
    try:
        subprocess.run([
            "iptables", "-D", "FORWARD",
            "-s", client_ip,
            "-d", resource_ip,
            "-p", proto,
            "-m" , "multiport",
            "--dports", str(port),
            "-j", "ACCEPT"
        ], check=True)

        print(f"[OK] Deleted ACCEPT rule for port {port}: {client_ip} -> {resource_ip}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Could not delete ACCEPT {port} rule: {e}")



def handle_request(cmd):
    action = cmd["action"]
    client_ip = cmd["client_vpn_ip"]
    resource_ip = cmd["resource_ip"]
    ports = cmd["ports"]         # list of ports
    proto = cmd.get("protocol")

    #for p in ports:
    if action == "Request_Access":
            print("[*] Executing Request Access")
            allow_access(client_ip, resource_ip, ports, proto)
        
    elif action == "Remove_Access":
            print("[*] Executing Remove Access")
            deny_access(client_ip, resource_ip, ports, proto)
        
    return True


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

            Request = command.get("action")

            if Request == "remove_peer":
                success = remove_peer(command["public_key"])
                if success:
                    conn.send(b"Peer removed")
                    print(f"[+] Removed peer {command['public_key']}")
                else:
                    conn.send(b"Peer not found")
                    print(f"[-] Peer {command['public_key']} not found")
            
            elif Request == "resync":
                success = strip_and_resync()
                if success:
                    conn.send(b"WireGuard configuration resynced successfully")
                    print("[*] WireGuard configuration resynced successfully.")
                else:
                    conn.send(b"Failed to resync configuration")
                    print("[!] Failed to resync WireGuard configuration.")

            elif Request == "Request_Access" or Request == "Remove_Access":
                success = handle_request(command)
                if success:
                    conn.send(b"Permission Granted Succesfully")
                    print(f"[*] {Request} Permission Granted Successfully")
                else:
                    conn.send(b"Failed to Process Request")
                    print(f"[!] Failed to Process {Request}")
            else:
                conn.send(b"Unknown action")
        except Exception as e:
            print("[!] Error handling client:", e)
        finally:
            conn.close()
except KeyboardInterrupt:
    print("\n[*] Server shutting down.")
    tls_sock.close()
