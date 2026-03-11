import socket
import json 
import sys 
import logging
import signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from IP_Address_Manager import *
import hmac
import hashlib
import time
import threading
import base64
import argparse
import pprint
import os
import ipaddress
import add_wg_peer
import subprocess
import Gateway_SSL 
import requests


class SPAServer:
    def __init__(self, config_file='server_config.json', verbose=False, port=62201, daemon=False):
        # Load configuration first
        self.load_config(config_file)
        
        # Apply config defaults first, then command line overrides
        self.verbose = self.config.get('verbose', False)
        self.port = self.config.get('listen_port', 62201)
        self.daemon = self.config.get('daemon', False)
        
        # Command line arguments override config file settings
        if verbose:
            self.verbose = verbose
        if port != 62201:  # Only override if non-default port specified
            self.port = port
        if daemon:
            self.daemon = daemon
        
        # Initialize other components
        self.setup_logging()
        self.setup_crypto()
        self.socket = None
        self.running = True
        # Track active Commuincation
        self.connection = False
        self.Enabled = False
        self.violation = True
        # Track received SPA packets
        self.spa_requests = {}
        self.recently_timed_out = {}
        self._lock = threading.Lock()
    

    def load_config(self, config_file): 
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logging.warning(f"Error: Configuration file {config_file} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logging.warning(f"Error: Invalid JSON in configuration file {config_file}: {e}")
            sys.exit(1)

    def is_duplicate(self,new_object: dict, file_path: str = "Client_History.json") -> bool:
        existing_data = []
        
        if not os.path.exists(file_path):
            return False
        
        try:
            with open(file_path, 'r') as f:
                file_content = f.read().strip()
                if file_content:
                    existing_data = json.loads(file_content)
        except json.JSONDecodeError:
            return False 
        
        if not isinstance(existing_data, list):
            return False

        try:
            new_string = json.dumps(new_object, sort_keys=True)
        except TypeError:
            return False 

        unique_set = set()
        for item in existing_data:
            try:
                unique_set.add(json.dumps(item, sort_keys=True))
            except TypeError:
                continue 

        return new_string in unique_set


    def store_access_event(self, packet):
        log_file = "Client_History.json"

        if self.is_duplicate(packet, log_file):
            logging.warning("[!] Duplicate event detected. Not storing.")
            return

        try:
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    data = json.load(f)
            else:
                data = []
        except:
            data = []

        data.append(packet)

        with open(log_file, "w") as f:
            json.dump(data, f, indent=4)

        logging.info(f"[+] Stored event: {packet}")



    def setup_logging(self):
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level = logging.DEBUG if self.verbose else logging.INFO
        handlers = []

        # Add file handler if specified in config
        if 'log_file' in self.config:
            try:
                file_handler = logging.FileHandler(self.config['log_file'])
                file_handler.setFormatter(logging.Formatter(log_format))
                handlers.append(file_handler)
            except Exception as e:
                logging.warning(f"Failed to set up file logger: {e}")

        # Add console handler if not daemon, or if verbose
        if self.verbose or not self.daemon:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(console_handler)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.handlers = []  # Clear existing handlers
        root_logger.setLevel(log_level)
        for handler in handlers:
            root_logger.addHandler(handler)
    
    def setup_crypto(self):
        # Derive AES key from encryption key
        if 'encryption_key' not in self.config:
            logging.warning("Error: encryption_key not found in configuration")
            sys.exit(1)
            
        password = self.config['encryption_key']
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # first 32 bytes for AES and next 32 for HMAC
            salt=b'ztna_salt',  # Fixed salt for consistency
            iterations=100000,
            backend=default_backend()
        )
        master_key = kdf.derive(password.encode('utf-8'))
        self.encryption_key = master_key[:32]
        self.hmac_key = master_key[32:]

    def verify_hmac(self, data, received_hmac):
        h = hmac.new(self.hmac_key, data, hashlib.sha256)
        return hmac.compare_digest(h.digest(), received_hmac)
    
    def decrypt_packet(self, encrypted_data):
        if len(encrypted_data) < 48:  # Minimum: 16 (IV) + 32 (HMAC) = 48 bytes
            raise ValueError("Packet too short")
            
        # Extract IV from the beginning of the packet
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        
        # Decrypt using AES-CBC
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Split data and HMAC
        json_data = data[:-32]  # HMAC is 32 bytes
        received_hmac = data[-32:]
        
        return json_data, received_hmac

    def generate_pool(self, subnet, gateway_ip):
        net = ipaddress.ip_network(subnet)
        return [
            str(ip)
            for ip in net.hosts()
                if str(ip) != gateway_ip
        ]

    def is_ip_allowed(self, ip):
        if 'allowed_ips' not in self.config:
            logging.warning("No allowed_ips configured - denying all access")
            return False
            
        allowed_list = self.config['allowed_ips']
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net in allowed_list:
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            return False
        except ValueError:
            return False

    def allocate_vpn_ip(self, device_id, gateway_id, vpn_subnet, lease_duration=600):

        conn = get_connection()
        cursor = conn.cursor()

        now = time.time()
        expiry = now + lease_duration

        # 1️⃣ Reuse existing active lease
        cursor.execute("""
            SELECT vpn_ip
            FROM vpn_leases
            WHERE device_id=? AND status='active' AND lease_expiry > ?
        """, (device_id, now))

        row = cursor.fetchone()
        if row:
            conn.close()
            logging.info(f"[IPAM] Reusing existing VPN IP {row[0]}")
            return row[0]

        # 2️⃣ Get used IPs
        cursor.execute("""
            SELECT vpn_ip
            FROM vpn_leases
            WHERE gateway_id=? AND status='active' AND lease_expiry > ?
        """, (gateway_id, now))

        used_ips = set(row[0] for row in cursor.execute(
            "SELECT vpn_ip FROM vpn_leases WHERE status='active'"
        ))

        # 3️⃣ Define subnet
        net = ipaddress.ip_network(vpn_subnet)

        # Get gateway VPN IP (do not assign to client)
        cursor.execute("""
            SELECT gateway_vpn_ip FROM gateways WHERE gateway_id=?
        """, (gateway_id,))
        row = cursor.fetchone()
        gateway_ip = row[0] if row else None

        # 4️⃣ Iterate through subnet
        for ip in net.hosts():
            ip_str = str(ip)

            if gateway_ip and ip_str == gateway_ip:
                continue

            if ip_str not in used_ips:
                try:
                    cursor.execute("""
                        INSERT INTO vpn_leases
                        (device_id, gateway_id, vpn_ip, status,
                        lease_start, last_seen, lease_expiry)
                        VALUES (?, ?, ?, 'active', ?, ?, ?)
                    """, (device_id, gateway_id, ip_str, now, now, expiry))

                    conn.commit()
                    conn.close()

                    logging.info(f"[IPAM] Allocated {ip_str} to {device_id}")
                    return ip_str

                except sqlite3.IntegrityError as e:
                    logging.warning(f"[IPAM] IntegrityError for {ip_str}: {e}")
                    continue

        conn.close()
        raise Exception("VPN IP pool exhausted")

    def ensure_device_exists(device_id, public_key, public_ip):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR IGNORE INTO devices
            (device_id, public_key, public_ip, status)
            VALUES (?, ?, ?, 'online')
        """, (device_id, public_key, public_ip))

        conn.commit()
        conn.close()

    def refresh_lease_in_db(self, device_id, duration=600):
        conn = get_connection()
        cursor = conn.cursor()
        new_expiry = time.time() + duration
        cursor.execute("""
            UPDATE vpn_leases 
            SET lease_expiry = ?, last_seen = ? 
            WHERE device_id = ? AND status = 'active'
        """, (new_expiry, time.time(), device_id))
        conn.commit()
        conn.close()

    def lease_monitor(self):
        while self.running:
            time.sleep(30)

            conn = get_connection()
            cursor = conn.cursor()

            now = time.time()

            cursor.execute("""
                SELECT lease_id, device_id, vpn_ip
                FROM vpn_leases
                WHERE status='active' AND lease_expiry < ?
            """, (now,))

            expired = cursor.fetchall()

            for lease_id, device_id, vpn_ip in expired:
                logging.warning(f"[IPAM] Lease expired for {vpn_ip}")

                # Remove WireGuard peer
                try:
                    Gateway_SSL.send_remove_peer(device_id)
                except Exception as e:
                    logging.error(f"Failed to remove peer {device_id}: {e}")

                # Mark lease expired
                cursor.execute("""
                    DELETE FROM vpn_leases
                    WHERE lease_id=?
                """, (lease_id,))

            conn.commit()
            conn.close()
    
    def revoke_lease(self, device_id):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT vpn_ip FROM vpn_leases
            WHERE device_id=? AND status='active'
        """, (device_id,))

        row = cursor.fetchone()
        if not row:
            conn.close()
            return

        vpn_ip = row[0]

        try:
            Gateway_SSL.send_remove_peer(device_id)
        except:
            pass

        cursor.execute("""
            UPDATE vpn_leases
            SET status='revoked'
            WHERE device_id=?
        """, (device_id,))

        conn.commit()
        conn.close()

        logging.warning(f"[IPAM] Lease revoked for {vpn_ip}")

    def sync_gateways_to_db(self):
        gateways = add_wg_peer.load_gateways()

        conn = get_connection()
        cursor = conn.cursor()

        for gateway in gateways:
            cursor.execute("""
                SELECT gateway_id FROM gateways WHERE gateway_id=?
            """, (gateway["gateway_id"],))

            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO gateways (
                        gateway_id,
                        name,
                        vpn_subnet,
                        gateway_vpn_ip,
                        wireguard_interface,
                        listen_port,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'online')
                """, (
                    gateway["gateway_id"],
                    gateway.get("name", "Gateway"),
                    gateway["vpn_subnet"],
                    gateway.get("gateway_vpn_ip", ""),
                    gateway.get("wireguard_interface", "wg0"),
                    gateway.get("listen_port", 51820)
                ))

        conn.commit()
        conn.close()

    def is_keepalive_packet(self, packet_data):
        """
        Determine if this is a keepalive packet based on content or timing
        You can customize this logic based on your specific requirements
        """
        # Check if this is a repeat request from the same source within a short time
        source_ip = packet_data.get('source_ip')
        access_port = packet_data.get('access_port')
        protocol = packet_data.get('protocol')
        
        key = f"{source_ip}:{access_port}:{protocol}"
        current_time = int(time.time())
        
        if key in self.spa_requests:
            last_request_time = self.spa_requests[key]['timestamp']
            # If same request within 300 seconds, consider it a keepalive
            if current_time - last_request_time < 300:
                return True
        
        return False
    
    def handle_packet(self, data, addr):
        peer_ip = addr[0]

        # Ignore packets from recently timed-out peers (probably WireGuard keepalives)
        if peer_ip in self.recently_timed_out:
            if time.time() - self.recently_timed_out[peer_ip] < 10:
                logging.warning(f"Ignoring packet from timed-out peer {peer_ip} — waiting for new SPA.")
                return
            else:
                # After 10 s grace, forget timeout entry
                del self.recently_timed_out[peer_ip]

        try:

            if self.verbose:
                logging.info(f"\nReceived packet from {addr[0]}:{addr[1]}")
                logging.info(f"Raw data (base64): {base64.b64encode(data).decode()}")
            
            # Decrypt the packet
            decrypted, received_hmac = self.decrypt_packet(data)
            
            if self.verbose:
                logging.info(f"Decrypted data: {decrypted}")
                logging.info(f"HMAC from packet: {received_hmac.hex()}")
            
            # Verify HMAC
            if not self.verify_hmac(decrypted, received_hmac):
                logging.warning(f"Invalid HMAC from {addr[0]}")
                self.reply(addr, False, is_keepalive=False)
                return
            
            # Parse the packet
            packet_data = json.loads(decrypted)
            
            if self.verbose:
                logging.info("\nPacket contents:")
                logging.info(pprint.pformat(packet_data))
            
            # Check if source IP is allowed
            source_ip = packet_data.get('source_ip')
            if not source_ip:
                logging.warning(f"No source_ip in packet from {addr[0]}")
                self.reply(addr, False, is_keepalive=False)
                return
                
            if not self.is_ip_allowed(source_ip):
                logging.warning(f"Unauthorized IP {source_ip}")
                self.reply(addr, False, is_keepalive=False)
                return
            
            # Check if protocol is allowed
            if 'allowed_protocols' in self.config:
                protocol = packet_data.get('protocol')
                if protocol not in self.config['allowed_protocols']:
                    logging.warning(f"Unauthorized protocol {protocol}")
                    self.reply(addr, False, is_keepalive=False)
                    return
            
            # Determine if this is a keepalive packet
            is_keepalive = self.is_keepalive_packet(packet_data)
            key = f"{source_ip}:{packet_data.get('access_port', '')}:{packet_data.get('protocol', '')}"

            if is_keepalive:
                # Keepalive → only update timestamp
                logging.info(f"Keepalive packet received from {source_ip}")
                with self._lock:
                    if key in self.spa_requests:
                        self.spa_requests[key]['timestamp'] = time.time()
                        device_id = self.spa_requests[key].get('public_key')
                        if device_id:
                            self.refresh_lease_in_db(device_id)
                    else:
                        logging.warning(f"Keepalive received for unknown peer {key}")
                self.reply(addr, True, is_keepalive=True)

            else:
                # SPA request → save full packet data
                self.spa_requests[key] = {
                    'timestamp': time.time(),
                    'data': packet_data
                }

                if not self.connection:
                    logging.info(f"Authorized SPA request: {key}")
                    self.reply(addr, True, is_keepalive=False, packet_data=packet_data)
                    self.connection = True  # mark connection as formed
                    self.Enabled = True
                else:
                    # Tunnel exists but packet is NOT a keepalive → ignore it
                    logging.warning(f"Unexpected packet from {source_ip} while connection already formed. Ignoring.")
                    self.reply(addr, False, is_keepalive=False)

            
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in packet from {addr[0]}: {e}")
            self.reply(addr, False, is_keepalive=False)
        except Exception as e:
            logging.error(f"Error processing packet from {addr[0]}: {str(e)}")
            self.reply(addr, False, is_keepalive=False)
            if self.verbose:
                import traceback
                traceback.print_exc()

    def receive_key(self, addr, packet_data):
        try:
            access_port = packet_data.get('access_port')
            self.socket.settimeout(10)  # Wait max 10s for the key
            data, sender = self.socket.recvfrom(4096)
            
            # Verify the sender is the same as the original requester
            if sender[0] != addr[0]:
                logging.warning(f"Key received from different IP: expected {addr[0]}, got {sender[0]}")
                return
                
            try:
                key = data.decode().strip()
            except UnicodeDecodeError:
                logging.warning(f"Invalid key encoding received from {addr[0]}")
                return
                
            if key:
                # Extract resource IP from the SPA packet data
                resource_id = packet_data.get('resource_ip')

                # ---------------- SAFE ONE-PHASE IP ALLOCATION ---------------- #

                gateways = add_wg_peer.load_gateways()
                gateway = add_wg_peer.resolve_gateway(resource_id, gateways)

                client_identifier = key  # WireGuard public key

                with self._lock:
                    try:
                        # 1️⃣ Ensure device exists in DB
                        conn = get_connection()
                        cursor = conn.cursor()

                        cursor.execute("""
                            INSERT OR IGNORE INTO devices
                            (device_id, public_key, public_ip, status)
                            VALUES (?, ?, ?, 'online')
                        """, (client_identifier, client_identifier, addr[0]))

                        conn.commit()
                        conn.close()

                        # 2️⃣ Allocate VPN IP
                        vpn_ip = self.allocate_vpn_ip(
                            device_id=client_identifier,
                            gateway_id=gateway["gateway_id"],
                            vpn_subnet=gateway["vpn_subnet"],
                            lease_duration=600
                        )

                    except Exception as e:
                        logging.error(f"[IPAM] {str(e)}")

                        error_response = json.dumps({
                            "status": "error",
                            "message": str(e)
                        }).encode()

                        self.socket.sendto(error_response, addr)
                        return

                # Persist immediately after allocation
                add_wg_peer.update_gateway(resource_id, gateways, gateway)

                if not gateway.get("gateway_vpn_ip"):

                    if not gateway.get("vpn_ip_pool"):
                        logging.critical("[IPAM] VPN IP POOL EXHAUSTED - Access Denied")
                        error_response = json.dumps({
                            "status": "error",
                            "message": "VPN IP pool exhausted"
                        }).encode()
                        self.socket.sendto(error_response, addr)
                        return
                    gw_vpn_ip = gateway["vpn_ip_pool"].pop(0)
                    gateway["gateway_vpn_ip"] = gw_vpn_ip
                    logging.info(f"[IPAM] Gateway VPN IP assigned: {gw_vpn_ip}")
                else:
                    gw_vpn_ip = gateway["gateway_vpn_ip"]

                # Persist changes immediately
                add_wg_peer.update_gateway(resource_id, gateways, gateway)

                client_ip = addr      # The peer’s public/external IP
                peer_pubkey = key         # WireGuard public key received

                if(self.verbose):
                    logging.info(f"Stored peer mapping: {client_ip} -> {peer_pubkey}")

                logging.info(f"WireGuard public key received from {addr[0]}: {key}")
                gateway['gateway_vpn_ip']=gw_vpn_ip
                
                # Add peer to WireGuard
                if not self.connection:
                    data = json.loads(Gateway_SSL.Generate_Wiregaurd(gw_vpn_ip,gateway['listen_port']))
                    Gateway_SSL.Start_Wireguard("Start")
                    

                add_wg_peer.add_peer(self,vpn_ip,key,gateway)
                packet = {
                    "action":"Request_Access",
                    "source_ip": vpn_ip,
                    "resource_ip": resource_id,
                    "port": packet_data["access_port"],
                    "protocol": packet_data["protocol"],
                }
                Gateway_SSL.Request_Permission("Request_Access",vpn_ip,add_wg_peer.Resource_Resolver(resource_id),access_port,packet_data["protocol"])
                self.store_access_event(packet)
                # response = requests.get("http://10.0.0.2:5000/auth/allow")
                # logging.info(response.json())
                # response=requests.get("http://10.0.0.2:5000/auth")
                # logging.info(response.json())


                gateway['wireguard_public_key'] = data.get("public_key")
                add_wg_peer.update_gateway(resource_id,gateways,gateway)
                # Prepare gateway details to send to client
                request_key = f"{addr[0]}:{packet_data.get('access_port')}:{packet_data.get('protocol')}"
                with self._lock:    
                    self.spa_requests[request_key] = {
                        "public_key": peer_pubkey,
                        "timestamp": time.time(),
                        "vpn_ip": vpn_ip

                    }

                gateway_details = {
                    'gateway_public_key': gateway['wireguard_public_key'],
                    'gateway_endpoint': f"{gateway['ssh_host']}:{gateway['listen_port']}",
                    'client_vpn_ip': vpn_ip,
                    'vpn_subnet': gateway['vpn_subnet'],
                    'gateway_vpn_ip': gw_vpn_ip,
                    'status': 'success'
                }   
                
                # Send gateway details as JSON response
                response = json.dumps(gateway_details).encode()
                self.socket.sendto(response, addr)
                
                logging.info(f"Gateway details sent to {addr[0]}: {gateway_details}")
                
            else:
                logging.warning(f"Empty key received from {addr[0]}")
                # Send error response
                error_response = json.dumps({'status': 'error', 'message': 'Empty key received'}).encode()
                self.socket.sendto(error_response, addr)

        except socket.timeout:
            logging.warning(f"No key received from {addr[0]} within timeout")
            # Send timeout response
            timeout_response = json.dumps({'status': 'error', 'message': 'Key timeout'}).encode()
            try:
                self.socket.sendto(timeout_response, addr)
            except:
                pass
        except Exception as e:
            logging.error(f"Error receiving key from {addr[0]}: {str(e)}")
            # Send error response
            error_response = json.dumps({'status': 'error', 'message': str(e)}).encode()
            try:
                self.socket.sendto(error_response, addr)
            except:
                pass
        finally:
            self.socket.settimeout(None)  

    def reply(self, addr, result, is_keepalive=False, packet_data=None):
        try:
            if result:
                if is_keepalive and self.connection:
                    self.socket.sendto('SPA Keepalive acknowledged'.encode(), addr)
                    if self.verbose:
                        logging.info(f"Keepalive acknowledged for {addr[0]}")
                elif not self.connection:
                    self.socket.sendto('SPA Verification successful'.encode(), addr)
                    self.receive_key(addr, packet_data)
                else:
                    logging.warning(f"Ignoring non-keepalive SPA packet from {addr[0]} (connection already active)")
                    self.socket.sendto('SPA already established'.encode(), addr)
            else:
                self.socket.sendto('SPA Verification Failed'.encode(), addr)
        except Exception as e:
            logging.error(f"Error sending reply to {addr[0]}: {str(e)}")


    def _peer_cleanup_thread(self):
        logging.info("Peer cleanup thread started.")
        PEER_TIMEOUT = self.config.get('peer_timeout', 120)

        while self.running:
            time.sleep(20)
            logging.debug("Cleanup thread awake and checking for timed-out peers.")

            now = time.time()
            peers_to_remove = []

            if not self.spa_requests:
                continue

            # Phase 1: Identify all timed-out peers
            with self._lock:
                for key, details in list(self.spa_requests.items()):
                    timestamp = details.get('timestamp', 0)
                    peer_pubkey = details.get('public_key')
                    age = now - timestamp
                    logging.debug(f"Checking peer '{key}' (pubkey={peer_pubkey}) — age {int(age)}s / timeout {PEER_TIMEOUT}s")

                    if age > PEER_TIMEOUT:
                        logging.warning(f"Peer '{key}' has timed out. Cleaning up...")
                        try:
                            if peer_pubkey:
                                response = Gateway_SSL.send_remove_peer(peer_pubkey)
                                logging.info(f"Gateway response for '{key}': {response.strip()}")
                            else:
                                logging.warning(f"No public key found for peer '{key}' — skipping removal request.")

                            # Mark for removal
                            peers_to_remove.append(key)

                        except Exception as e:
                            logging.error(f"Failed to contact gateway for '{key}': {e}")
                            
                    port = key.split(":")[1]
                    proto = key.split(":")[2]

                    if age > PEER_TIMEOUT:
                        try:
                            with open("Client_History.json", "r") as f:
                                client_history = json.load(f)
                        except FileNotFoundError:
                            logging.info("[!] Client_History.json not found")
                            client_history = []
                        except Exception as e:
                            logging.error(f"Failed to read Client_History.json: {e}")
                            client_history = []

                        for entry in client_history:
                            if(port == entry.get("port") and proto == entry.get("protocol")):
                                try:
                                    Gateway_SSL.Request_Permission(
                                        "Remove_Access",
                                        entry.get("source_ip"),
                                        add_wg_peer.Resource_Resolver(entry.get("resource_ip")),
                                        entry.get("port"),
                                        entry.get("protocol")  # make sure JSON uses "protocol", not "portocol"
                                    )
                                except Exception as e:
                                    logging.error(f"Failed to contact gateway for {entry}: {e}")
                            

            # Phase 2: Actually remove timed-out peers
            if peers_to_remove: 
                with self._lock:
                    for key in peers_to_remove:
                        peer_info = self.spa_requests.pop(key, None)
                        if peer_info:
                            pubkey = peer_info.get('public_key', 'unknown')
                            logging.info(f"Removed peer '{key}' (pubkey={pubkey}) from SPA table.")
                            
                            # Optional: Remove peer from WireGuard config
                            try:
                                if hasattr(add_wg_peer, 'remove_peer'):
                                    Gateway_SSL.send_remove_peer(pubkey)
                                    logging.info(f"Peer '{key}' also removed from WireGuard config.")
                            except Exception as e:
                                logging.warning(f"Failed to remove peer '{key}' from WireGuard: {e}")

                            # ✅ Completely delete peer info from memory
                            if hasattr(self, 'active_peers') and key in self.active_peers:
                                del self.active_peers[key]
                            if hasattr(self, 'hmac_table') and key in self.hmac_table:
                                del self.hmac_table[key]


                # ✅ Mark peer's IP as recently timed out
                peer_ip = key.split(":")[0]
                self.recently_timed_out[peer_ip] = time.time()
                logging.info(f"Marked {peer_ip} as recently timed out.")

                # Reset connection state if no active peers left
                with self._lock:
                    if not self.spa_requests:
                        self.connection = False
                        logging.info("All peers cleaned up — connection flag reset to False.")
                                #  After all timed-out peers are cleaned up, resync Gateway
                try:
                    logging.info("Triggering Gateway WireGuard resync...")
                    response = Gateway_SSL.send_resync()
                    logging.info(f"Gateway resync response: {response.strip()}")
                except Exception as e:
                    logging.error(f"Failed to trigger Gateway resync: {e}")

            
    def start(self):    
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            logging.info(f"Server started on port {self.port}")
            logging.info(f"Listening on all interfaces (0.0.0.0)")
            
            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            self.sync_gateways_to_db()
            cleanup_thread = threading.Thread(target=self._peer_cleanup_thread, daemon=True)
            lease_thread = threading.Thread(target=self.lease_monitor, daemon=True)  

            cleanup_thread.start()
            lease_thread.start() 
            Gateway_SSL.Refresh_Gateway_Firewall() 
            # verification_thread.start()
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    self.handle_packet(data, addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  
                        logging.error(f"Error processing packet: {str(e)}")
                    continue
                    
        except KeyboardInterrupt:
            logging.info("Received KeyboardInterrupt, shutting down...")
        except Exception as e:
            logging.error(f"Server error: {str(e)}")    
        finally:
            self.cleanup()

    def signal_handler(self, signum, frame):
        if not self.running:  # Prevent multiple shutdown attempts
            return
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def cleanup(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        logging.info("Server shutdown complete")

def main():
    parser = argparse.ArgumentParser(
        description='SPA Server - Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Start server on default port (62201):
    python3 spa_server.py

  Start server on custom port with verbose output:
    python3 spa_server.py -p 12345 -v

  Start server in daemon mode:
    python3 spa_server.py --daemon

  Use custom config file:
    python3 spa_server.py -c custom_config.json
''')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show verbose output including packet details')
    parser.add_argument('-c', '--config', default='server_config.json',
                      help='Path to config file (default: server_config.json)')
    parser.add_argument('-p', '--port', type=int, default=62201,
                      help='Port to listen on (default: 62201)')
    parser.add_argument('--daemon', action='store_true',
                      help='Run server in daemon mode')
    args = parser.parse_args()

    if args.daemon:
        # Daemonize the process
        try:
            pid = os.fork()
            if pid > 0:
                # Parent process exits
                sys.exit(0)
        except OSError as e:
            logging.info(f"Fork failed: {e}")
            sys.exit(1)

        # Create new session
        os.setsid()
        os.umask(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    server = SPAServer(config_file=args.config, verbose=args.verbose, 
                      port=args.port, daemon=args.daemon)
    try:
        
        server.start()
    except KeyboardInterrupt:
        server.cleanup()

if __name__ == "__main__":
    init_db()
    main()