import subprocess
import sys
import json

def load_gateways(json_path="sdp_gateway_details.json"):
    try:
        with open(json_path, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"Failed to load gateways: {e}")
        sys.exit(1)

def resolve_gateway(resource_ip, gateways):
    resource_to_gateway_id = {
        "resource-1": "gw-01",
        "resource-2": "gw-02"
    }

    gateway_id = resource_to_gateway_id.get(resource_ip)
    if not gateway_id:
        print(f"Invalid resource identifier: {resource_ip}")
        return

    for gw in gateways:
        if gw["gateway_id"] == gateway_id:
            return gw

    print(f"Gateway with ID '{gateway_id}' not found.")
    return None

def add_peer(client_vpn_ip, client_pub_key, resource_id, gateway):

    ssh_user = gateway["ssh_user"]
    ssh_host = gateway["ssh_host"]
    ssh_port = gateway["ssh_port"]
    ssh_key_path = gateway["ssh_key_path"]
    wg_interface = gateway["wireguard_interface"]  # e.g., 'wg0'


    wg_cmd = f" sudo wg set {wg_interface} peer {client_pub_key} allowed-ips {client_vpn_ip}/32"
    ssh_command = [
        "ssh",
        "-i", ssh_key_path,
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
        wg_cmd
    ]
    print(f"\n [+] Connecting to {gateway['name']} ({ssh_host}) using key {ssh_key_path}...\n")

    
    try:
        result = subprocess.run(ssh_command, capture_output=True, text=True, check=True)
        print("[+] Peer successfully added to live WireGuard interface.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to run wg command:\n{e.stderr}")
    except Exception as ex:
        print(f"[!] Unexpected error: {ex}")

# # -------- Execution --------
# gateways = load_gateways()  # now returns the list
# gateway = resolve_gateway("resource-1", gateways)
# selcted_gateway = add_peer("recource-1",gateway)