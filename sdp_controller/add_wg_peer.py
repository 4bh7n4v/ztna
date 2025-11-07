import subprocess
import sys
import json
import os
import logging
import ipaddress


WG_CONF_PATH = "/etc/wireguard/wg0.conf"
GATEWAY_FILE_PATH = "sdp_gateway_details.json" # Make sure this matches the filename you use

def load_gateways(json_path="sdp_gateway_details.json"):
    try:
        with open(json_path, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"Failed to load gateways: {e}")
        sys.exit(1)

def resolve_gateway(resource_ip, gateways):
    resource_to_gateway_id = {
        "resource1.local": "gw-01",
        "resource2.local": "gw-02"
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

def Resource_Resolver(resource_id):
    DNS = {
        "resource1.local": "192.168.1.101",
        "resource2.local": "192.168.2.101"
    }
    resource_ip = DNS.get(resource_id)
    if not resource_ip:
        print(f"Invalid resource identifier: {resource_ip}")
        return
    
    return resource_ip

def update_gateway(resource_ip, gateways, updated_gateway, file_path="sdp_gateway_details.json"):
    gateway_id = {
        "resource1.local": "gw-01",
        "resource2.local": "gw-02"
    }.get(resource_ip)

    if not gateway_id:
        print(f"[!] Invalid resource identifier: {resource_ip}")
        return False

    updated = False
    for i, gw in enumerate(gateways):
        if gw["gateway_id"] == gateway_id:
            gateways[i] = updated_gateway  # Replace the entire gateway dict
            updated = True
            break

    if updated:
        with open(file_path, "w") as f:
            json.dump(gateways, f, indent=2)
        print(f"[+] Gateway {gateway_id} updated successfully.")
        return True
    else:
        print(f"[!] Gateway with ID '{gateway_id}' not found.")
        return False


def return_ip_to_pool(ip_address):
    """
    (Helper function) Adds an IP address back to the available pool in the gateway details JSON.
    """
    try:
        with open(GATEWAY_FILE_PATH, 'r') as f:
            gateways = json.load(f)

        ip_obj = ipaddress.ip_address(ip_address)
        gateway_found = False

        for name, details in gateways.items():
            subnet = ipaddress.ip_network(details['vpn_subnet'])
            if ip_obj in subnet:
                if ip_address not in details['vpn_ip_pool']:
                    details['vpn_ip_pool'].append(ip_address)
                    logging.info(f"Returned IP {ip_address} to the pool for gateway '{name}'.")
                else:
                    logging.warning(f"IP {ip_address} was already in the pool for gateway '{name}'.")
                gateway_found = True
                break
        
        if not gateway_found:
            logging.warning(f"Could not find a matching gateway for IP {ip_address} to return it to the pool.")
            return

        with open(GATEWAY_FILE_PATH, 'w') as f:
            json.dump(gateways, f, indent=4)

    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        logging.error(f"Could not return IP to pool. Error with {GATEWAY_FILE_PATH}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred in return_ip_to_pool: {e}")


def add_peer(server, client_vpn_ip, client_pub_key, gateway):

    ssh_user = gateway["ssh_user"]
    ssh_host = gateway["ssh_host"]
    ssh_port = gateway["ssh_port"]
    ssh_key_path = gateway["ssh_key_path"]
    wg_interface = gateway["wireguard_interface"]  


# gateway dioesnt require endpoints

    append_cmd = (
        f'echo -e "\\t[Peer]\\n\\tPublicKey = {client_pub_key}\\n\\tAllowedIPs = {client_vpn_ip}"'
        f'>> /tmp/wireguard/{wg_interface}.conf'
    )

    if not server.connection and not server.Enabled:
        # Intial User
        wg_cmd = f"{append_cmd} && sudo wg-quick up /tmp/wireguard/{wg_interface}.conf"
    elif server.Enabled:
    # Multi-User — reload config safely
        wg_cmd = f"{append_cmd} && sudo wg-quick strip /tmp/wireguard/wg0.conf > /tmp/wireguard/stripped.conf && \
                    sudo wg syncconf wg0 /tmp/wireguard/stripped.conf && \
                    rm -f /tmp/wireguard/stripped.conf"


    ssh_command = [
        "ssh", "-v",
        "-i", ssh_key_path,
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
        f"bash -c '{wg_cmd}'"
    ]
    print(f"\n [+] Connecting to {gateway['name']} ({ssh_host}) using key {ssh_key_path}...\n")

    
    try:
        print(f"[+] Executing WireGuard Command")
        result = subprocess.run(ssh_command)
        print("[+] Peer successfully added to live WireGuard interface.")

        server.connection = True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to run wg command:\n{e.stderr}")
    except Exception as ex:
        print(f"[!] Unexpected error: {ex}")

def Copy_inference(gateway):
    ssh_user = gateway["ssh_user"]
    ssh_host = gateway["ssh_host"]  
    ssh_port = gateway["ssh_port"]
    ssh_key_path = gateway["ssh_key_path"]
    wireguard_conf_path = gateway["wireguard_conf_path"]
    remote_path = f"/tmp/wireguard/{gateway['wireguard_interface']}.conf"


    # Ensure local file exists
    if not os.path.isfile(wireguard_conf_path):
        print(f"[!] Local file '{wireguard_conf_path}' not found.")
    else:
        # Build the SCP command
        scp_command = [
            "scp", "-v",                     
            "-i", ssh_key_path,
            "-P", str(ssh_port),
            wireguard_conf_path,
            f"{ssh_user}@{ssh_host}:{remote_path}"
        ]

        print(f"\n[+] Uploading '{wireguard_conf_path}' to {gateway['name']} ({ssh_host})...\n")

        # Execute SCP command
        try:
            subprocess.run(scp_command, check=True)
            print("[+] File transferred successfully via SCP.")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to transfer file to {gateway['name']}.\nError: {e}")

def update_wg0_conf(private_key, address, port, conf_path="/home/uneedituh/ztna/sdp_gateway/wg0.conf"):
    """
    Always write a fresh wg0.conf file with the given [Interface] section.

    Parameters:
        private_key (str): WireGuard private key.
        address (str): VPN subnet address (e.g., 10.0.0.1/24).
        port (int or str): Listening port for WireGuard.
        conf_path (str): Path where the wg0.conf file will be written.
    """
    interface_block = f"""# /etc/wireguard/wg0.conf (server)
        [Interface]
        PrivateKey = {private_key}
        Address = {address}
        ListenPort = {port}

        #Wiregaurd handshake 

            
        """
    
        # Allow WireGuard handshake only


    try:
        with open(conf_path, 'w') as f:
            f.write(interface_block)
        print(f"[+] New wg0.conf file written to: {conf_path}")
    except Exception as e:
        print(f"[!] Failed to write wg0.conf: {e}") 

# # -------- Execution --------
# gateways = load_gateways()  # now returns the list
# gateway = resolve_gateway("resource-1", gateways)
# selcted_gateway = add_peer("recource-1",gateway)