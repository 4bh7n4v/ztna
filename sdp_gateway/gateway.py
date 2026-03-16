import json
import ssl
import os
import fcntl
import socket
import logging
import subprocess
import wireguard
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

WG_CONF_FILE = "/tmp/PEP_workspace/wg0.conf"
RUNTIME_CONF = "/tmp/PEP_workspace/runtime.conf"

def _ok(payload: dict) -> dict:
    return {"status": "success", **payload}

def _err(error_type: str, message: str) -> dict:
    return {"status": "error", "error_type": error_type, "message": message}

def _send(conn, data):
    """
    Send data over TLS connection.
    Accepts: dict (serialized to JSON bytes), str (encoded to bytes), bytes/bytearray
    Raises: TypeError for anything else (bool, int, None, etc.)
    """
    if isinstance(data, dict):
        conn.send(json.dumps(data).encode("utf-8"))
    elif isinstance(data, str):
        conn.send(data.encode("utf-8"))
    elif isinstance(data, (bytes, bytearray)):
        conn.send(data)
    else:
        raise TypeError(
            f"_send received unsupported type: {type(data).__name__} — "
            f"expected dict, str, or bytes. Value: {repr(data)}"
        )

def apply_firewall():
    def run(cmd):
        try:
            subprocess.run(cmd, check=True)
            logging.info(f"[OK] {' '.join(cmd)}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"[ERROR] {' '.join(cmd)}\n{e}")
            return False

    # Resolve controller.local first
    try:
        controller_ip = socket.gethostbyname("controller.local")
        logging.info(f"[+] Resolved controller.local -> {controller_ip}")
    except socket.gaierror as e:
        logging.error(f"[!] Failed to resolve controller.local: {e}")
        return _err("DNSError", f"Failed to resolve controller.local: {e}")

    rules = [
        # --- Flush existing rules ---
        ["iptables", "-F"],
        ["iptables", "-X"],
        ["iptables", "-t", "nat",    "-F"],
        ["iptables", "-t", "mangle", "-F"],

        # --- Loopback ---
        ["iptables", "-A", "INPUT",  "-i", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],

        # --- Established/related ---
        ["iptables", "-A", "INPUT",  "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],

        # --- ICMP only to/from controller.local ---
        ["iptables", "-A", "OUTPUT", "-p", "icmp", "-d", controller_ip, "-j", "ACCEPT"],
        ["iptables", "-A", "INPUT",  "-p", "icmp", "-s", controller_ip, "-j", "ACCEPT"],

        # --- TLS: Zero Trust control plane ---
        ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "4433",
         "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"],

        # --- WireGuard: data plane tunnel ---
        ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "51820",
         "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"],
    ]

    drop_policies = [
        ["iptables", "-P", "INPUT",   "DROP"],
        ["iptables", "-P", "FORWARD", "DROP"],
        ["iptables", "-P", "OUTPUT",  "DROP"],
    ]

    for rule in rules:
        if not run(rule):
            return _err("FirewallError", "Firewall configuration failed during rule setup")

    for policy in drop_policies:
        if not run(policy):
            return _err("FirewallError", "Firewall configuration failed during DROP policy setup")

    logging.info("[SUCCESS] Zero Trust Gateway firewall applied.")
    logging.info(f"  Allowed : TCP 4443 (TLS), UDP 51820 (WireGuard), loopback")
    logging.info(f"  Allowed : ICMP to/from controller.local ({controller_ip}) only")
    logging.info(f"  Blocked : ICMP from all other IPs, SSH, and all other traffic")
    return _ok({"message": f"Firewall applied. ICMP allowed only to/from controller.local ({controller_ip})"})


def strip_and_resync():
    try:
        subprocess.run(
            f"wg-quick strip {WG_CONF_FILE} | tee {RUNTIME_CONF} > /dev/null",
            shell=True,
            check=True
        )
        subprocess.run(
            ["wg", "syncconf", "wg0", RUNTIME_CONF],
            check=True
        )
        logging.info("[*] WireGuard configuration successfully stripped and synced.")
        return _ok({"message": "WireGuard configuration resynced successfully"})

    except subprocess.CalledProcessError as e:
        logging.warning("[!] Failed to strip or sync configuration: %s", e)
        return _err("SubprocessError", f"Failed to strip or sync configuration: {e}")

    except Exception as e:
        logging.exception("[!] Unexpected error during resync")
        return _err(type(e).__name__, str(e))

def remove_peer(pub_key):
    try:
        with open(WG_CONF_FILE, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return _err("FileNotFoundError", f"Config file not found: {WG_CONF_FILE}")

    out = []
    block = []
    skip = False
    found = False

    for line in lines:
        if line.strip() == "[Peer]":
            if block:
                if not skip:
                    out.extend(block)
            block = [line]
            skip = False
            continue

        block.append(line)

        if line.strip().replace(" ", "").startswith("PublicKey=") and pub_key in line:
            skip = True
            found = True

    if block and not skip:
        out.extend(block)

    if not found:
        return _err("PeerNotFound", f"Peer '{pub_key}' not found")

    try:
        with open(WG_CONF_FILE, "w") as f:
            f.writelines(out)

        logging.info("[+] Peer %s removed from config", pub_key)

        sync = strip_and_resync()
        if sync["status"] != "success":
            return _err("ResyncError", "Peer removed from file but resync failed")

        return _ok({"message": f"Peer {pub_key} removed successfully"})

    except PermissionError as e:
        return _err("PermissionError", f"Permission denied modifying config: {e}")

    except Exception as e:
        logging.exception("[!] Unexpected error removing peer")
        return _err(type(e).__name__, str(e))
        
def allow_access(client_ip, resource_ip, ports, proto):
    errors = []

    # Normalize ports to comma-separated string for multiport
    if isinstance(ports, list):
        ports_str = ",".join(str(p) for p in ports)
    else:
        ports_str = str(ports)

    # 1. Allow client → resource on specific port(s)
    try:
        subprocess.run([
            "iptables", "-I", "FORWARD", "1",
            "-s", client_ip,
            "-d", resource_ip,
            "-p", proto,
            "-m", "multiport",
            "--dports", ports_str,
            "-j", "ACCEPT"
        ], check=True)
        logging.info(f"[OK] ACCEPT rule added for ports {ports_str}: {client_ip} -> {resource_ip}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[ERROR] Failed to add ACCEPT {ports_str} rule: {e}")
        errors.append(f"ACCEPT rule failed: {e}")

    # 2. Allow return traffic resource → client
    try:
        subprocess.run([
            "iptables", "-I", "FORWARD", "2",
            "-d", client_ip,
            "-s", resource_ip,
            "-m", "state",
            "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ], check=True)
        logging.info(f"[OK] Return traffic rule added: {resource_ip} -> {client_ip}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[ERROR] Failed to add return traffic rule: {e}")
        errors.append(f"Return traffic rule failed: {e}")

    # 3. Drop everything else client → resource
    try:
        subprocess.run([
            "iptables", "-I", "FORWARD", "3",
            "-s", client_ip,
            "-d", resource_ip,
            "-j", "DROP"
        ], check=True)
        logging.info(f"[OK] DROP rule added: {client_ip} -> {resource_ip}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[ERROR] Failed to add DROP rule: {e}")
        errors.append(f"DROP rule failed: {e}")

    if errors:
        return _err("IPTablesError", "; ".join(errors))
    return _ok({"message": f"Access granted: {client_ip} -> {resource_ip}:{ports_str}"})

def deny_access(client_ip, resource_ip, ports, proto):
    errors = []
    
    # Normalize ports to a comma-separated string for multiport
    # Handles both single int (22), list ([22, 8080]), and already-formatted string ("22,8080")
    if isinstance(ports, list):
        ports_str = ",".join(str(p) for p in ports)
    else:
        ports_str = str(ports)

    # 3. Delete DROP rule
    try:
        subprocess.run([
            "iptables", "-D", "FORWARD",
            "-s", client_ip,
            "-d", resource_ip,
            "-j", "DROP"
        ], check=True)
        logging.info(f"[OK] Deleted DROP rule: {client_ip} -> {resource_ip}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[ERROR] Could not delete DROP rule: {e}")
        errors.append(f"DROP rule delete failed: {e}")

    # 2. Delete return traffic rule
    try:
        subprocess.run([
            "iptables", "-D", "FORWARD",
            "-d", client_ip,
            "-s", resource_ip,
            "-m", "state",
            "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ], check=True)
        logging.info(f"[OK] Deleted return traffic rule: {resource_ip} -> {client_ip}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[ERROR] Could not delete return traffic rule: {e}")
        errors.append(f"Return traffic rule delete failed: {e}")

    # 1. Delete ACCEPT rule
    try:
        subprocess.run([
            "iptables", "-D", "FORWARD",
            "-s", client_ip,
            "-d", resource_ip,
            "-p", proto,
            "-m", "multiport",
            "--dports", ports_str,   # ✅ "22,8080" instead of "[22, 8080]"
            "-j", "ACCEPT"
        ], check=True)
        logging.info(f"[OK] Deleted ACCEPT rule for ports {ports_str}: {client_ip} -> {resource_ip}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[ERROR] Could not delete ACCEPT {ports_str} rule: {e}")
        errors.append(f"ACCEPT rule delete failed: {e}")

    if errors:
        return _err("IPTablesError", "; ".join(errors))
    return _ok({"message": f"Access denied: {client_ip} -> {resource_ip}:{ports_str}"})

def Generate_Wireguard(cmd):
    try:
        address = cmd.get("Address")
        port    = cmd.get("ListenPort")

        if not address or not port:
            return _err("ValidationError", "Missing required fields: 'Address' or 'ListenPort'")

        priv = wireguard.get_private()
        pub  = wireguard.get_public_key()

        config_content = f"""[Interface]
PrivateKey = {priv}
Address = {address}/24
ListenPort = {port}
"""

        os.makedirs("/tmp/PEP_workspace", exist_ok=True)

        subprocess.run(
            ["tee", WG_CONF_FILE],
            input=config_content,
            capture_output=True,
            text=True,
            check=True
        )
        subprocess.run(["chmod", "600", WG_CONF_FILE], check=True)

        logging.info(f"[+] WireGuard configuration written to {WG_CONF_FILE}")
        logging.info(f"[+] Public Key: {pub}")

        return _ok({"address": address, "public_key": str(pub)})

    except subprocess.CalledProcessError as e:
        logging.error(f"[!] Subprocess error during config generation: {e}")
        return _err("SubprocessError", f"Command failed: {e.stderr or str(e)}")

    except PermissionError as e:
        logging.error(f"[!] Permission error: {e}")
        return _err("PermissionError", f"Permission denied: {e}")

    except Exception as e:
        logging.exception("[!] Unexpected error generating WireGuard config")
        return _err(type(e).__name__, str(e))

def Start_Wireguard():
    try:
        subprocess.run([
            "/usr/bin/wg-quick", "up", WG_CONF_FILE
        ], check=True)
        logging.info("[+] WireGuard interface is UP")
        return _ok({"message": "WireGuard tunnel activated successfully"})

    except subprocess.CalledProcessError as e:
        logging.error(f"[!] Could not bring up WireGuard interface: {e}")
        return _err("SubprocessError", f"wg-quick up failed: {e}")

    except Exception as e:
        logging.exception("[!] Unexpected error starting WireGuard")
        return _err(type(e).__name__, str(e))

def Add_Details(cmd):
    iface    = "wg0"
    conf_file = Path(f"/tmp/PEP_workspace/{iface}.conf")
    tmp_file  = Path(f"/tmp/PEP_workspace/{iface}_stripped.conf")

    try:
        pub_key = cmd.get("public_key")
        vpn_ip  = cmd.get("Vpn_ip")

        if not pub_key or not vpn_ip:
            return _err("ValidationError", "Missing required fields: 'public_key' or 'Vpn_ip'")

        peer_block = (
            f"\n[Peer]\n"
            f"PublicKey = {pub_key}\n"
            f"AllowedIPs = {vpn_ip}\n"
        )

        logging.info("[*] Appending new peer block to %s", conf_file)
        with open(conf_file, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write("\n" + peer_block.strip() + "\n")
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)
        logging.info("[+] Peer block appended successfully")

        logging.info("[*] Running: wg-quick strip %s", conf_file)
        with open(tmp_file, "w") as f:
            subprocess.run(
                ["/usr/bin/wg-quick", "strip", str(conf_file)],
                stdout=f,
                check=True
            )
        logging.info("[+] Strip completed successfully")

        logging.info("[*] Running: wg syncconf %s %s", iface, tmp_file)
        subprocess.run(
            ["/usr/bin/wg", "syncconf", iface, str(tmp_file)],
            check=True
        )
        logging.info("[+] syncconf successful on interface %s", iface)

        tmp_file.unlink(missing_ok=True)
        logging.info("[+] Peer %s added successfully to %s", pub_key, iface)

        return _ok({"message": f"Peer {pub_key} added successfully"})

    except subprocess.CalledProcessError as e:
        logging.error("[!] WireGuard command failed: %s", e)
        return _err("SubprocessError", f"WireGuard command failed: {e}")

    except PermissionError as e:
        logging.error("[!] Permission error while modifying config: %s", e)
        return _err("PermissionError", str(e))

    except OSError as e:
        logging.error("[!] File operation failed: %s", e)
        return _err("OSError", str(e))

    except Exception as e:
        logging.exception("[!] Unexpected error while adding peer")
        return _err(type(e).__name__, str(e))

def handle_request(cmd):
    action      = cmd["action"]
    client_ip   = cmd["client_vpn_ip"]
    resource_ip = cmd["resource_ip"]
    ports       = cmd["ports"]
    proto       = cmd.get("protocol")

    # Add this fix
    if isinstance(ports, list):
        ports = ",".join(str(p) for p in ports)

    if not all([client_ip, resource_ip, ports, proto]):
        return _err("ValidationError", "Missing required fields in request command")

    if action == "Request_Access":
        logging.info("[*] Executing Request Access")
        return allow_access(client_ip, resource_ip, ports, proto)

    elif action == "Remove_Access":
        logging.info("[*] Executing Remove Access")
        return deny_access(client_ip, resource_ip, ports, proto)

    return _err("UnknownAction", f"Unknown action: {action}")

# ===== TLS Server Setup =====
LISTEN_IP   = "10.0.2.254"                        # SDPGateway-eth0
LISTEN_PORT = 4433                                 # matches PORT_MTLS

CA_FILE     = "/tmp/CA_workspace/ca.crt"
SERVER_CERT = "/tmp/SDPGateway_workspace/PEP.crt"
SERVER_KEY  = "/tmp/SDPGateway_workspace/PEP.key"



context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
context.load_verify_locations(cafile=CA_FILE)
context.verify_mode = ssl.CERT_REQUIRED

    # Raw socket — bind and listen first
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((LISTEN_IP, LISTEN_PORT))
sock.listen(5)
logging.info("[*] Gateway TLS server listening on %s:%d", LISTEN_IP, LISTEN_PORT)

try:
    while True:
        conn, addr = sock.accept()
        logging.info(f"[*] Connection from {addr}")
        try:
            # ── ADD THIS LINE ──────────────────────
            tls_conn = context.wrap_socket(conn, server_side=True)
            # ──────────────────────────────────────

            data   = tls_conn.recv(4096)  # ← read from TLS not raw

            if not data:
                logging.warning("[!] Empty data from %s", addr)
                tls_conn.close()
                continue

            req    = json.loads(data.decode('utf-8'))
            action = req.get("action")

            if action == "remove_peer":
                res = remove_peer(req["public_key"])
            elif action == "Generate_keys":
                res = Generate_Wireguard(req)
            elif action == "load_Peer":
                res = Add_Details(req)
            elif action == "Start":
                res = Start_Wireguard()
            elif action == "resync":
                res = strip_and_resync()
            elif action == "Refresh_Rules":
                res = apply_firewall()
            elif action in ("Request_Access", "Remove_Access"):
                res = handle_request(req)
            else:
                res = _err("UnknownAction", f"Unknown action: {action}")

            # ── send response over TLS ──────────────
            _send(tls_conn, res)
            # ──────────────────────────────────────

            if res["status"] == "success":
                logging.info(f"[+] Action '{action}' completed successfully")
            else:
                logging.warning(f"[!] Action '{action}' failed: {res.get('message')}")

        except ssl.SSLError as e:
            logging.error(f"[!] TLS error from {addr}: {e}")
        except json.JSONDecodeError as e:
            logging.warning(f"[!] Invalid JSON from {addr}: {e}")
        except UnicodeDecodeError as e:
            logging.error(f"[!] Bad bytes from {addr}: {e}")
        except Exception as e:
            logging.exception(f"[!] Unexpected error handling client {addr}")
        finally:
            conn.close()

except KeyboardInterrupt:
    logging.info("\n[*] Server shutting down.")
    sock.close()