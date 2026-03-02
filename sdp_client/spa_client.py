import socket
import json
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import time
import pprint
import hmac
import hashlib
import base64
import threading
import argparse
import wireguard
import subprocess
import logging


WG_INTERFACE = "wg0"
THRESHOLD = 600  # seconds (10 min)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class SPAClient:
    def __init__(self, config_file='client_config.json', verbose=False, access_port=None, 
             server_port=62201, protocol='tcp', source_ip=None, keepalive_interval=240,interface="wg0"):
        # Initialize verbose first so it can be used in load_config
        self.verbose = verbose
        self.connection = 0
        
        # Load configuration
        self.load_config(config_file)
        
        # Apply config defaults first, then command line overrides
        if not verbose:  # Only use config verbose if command line wasn't specified
            self.verbose = self.config.get('verbose', False)
        self.keepalive_interval = self.config.get('keepalive_interval', 240)
        
        # Command line arguments override config file settings
        if access_port:
            self.config['access_port'] = access_port
        if source_ip:
            self.config['source_ip'] = source_ip
        if server_port != 62201:  # Only override if non-default port specified
            self.config['server_port'] = server_port
        if protocol != 'tcp':  # Only override if non-default protocol specified
            self.config['protocol'] = protocol
        if keepalive_interval != 240:  # Only override if non-default interval specified
            self.keepalive_interval = keepalive_interval
        
        self.setup_crypto(self.password)
        self.keepalive_timer = None

        self.interface = interface
        self.monitor_script = "/home/zerotrust/Desktop/ztna/sdp_client/wg_stale_monitor.py"
        self.stale_timeout = 300

    def dns(self,query):
        try:
            ip = socket.gethostbyname(query)
            return ip
        except socket.gaierror:
            return None

    def Update_DNS(self,config_file, save=False):
        """Load JSON, update server_ip using DNS, return updated config.
       If save=True -> write back to file."""
    
        with open(config_file) as f:
            cfg = json.load(f)
        
        # Update ONLY server_ip
        resolved_ip = self.dns(cfg["server_ip"])
        if resolved_ip:
            cfg["server_ip"] = resolved_ip

        # Save only if asked
        if save:
            with open(config_file, "w") as f:
                json.dump(cfg, f, indent=4)

        return cfg


    def get_client_ip(self):
        try:
            # This runs a shell command to find the IP on the PDP interface
            cmd = "ip addr show Intiating-eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1"
            ip = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            return ip if ip else "127.0.0.1"
        except Exception:
            return "127.0.0.1"

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                # self.config = json.load(f)
                self.config = self.Update_DNS(config_file)
            if not self.config.get("source_ip"):
                self.config['source_ip'] = self.get_client_ip() # get client ip using sockets
            self.password = self.config['encryption_key'] # get the encryptionkey from config file
        except FileNotFoundError:
            logging.warning(f"Error: Configuration file {config_file} not found")
            sys.exit(1)
        except json.JSONDecodeError:
            logging.warning(f"Error: Invalid JSON in configuration file {config_file}")
            sys.exit(1)
        if self.verbose:
                logging.info(f"Detected source IP: {self.config['source_ip']}")

    def Create_Conf(self,response):
        try:
            client_ip = response["client_vpn_ip"]
            gateway_pubkey = response["gateway_public_key"]
            endpoint = response["gateway_endpoint"]
            resource_ip = response["gateway_vpn_ip"]
            vpn_subnet = response["vpn_subnet"]

            config = f"""[Interface]
                PrivateKey = {wireguard.get_private_key()}
                Address = {client_ip}/24

                [Peer]
                PublicKey = {gateway_pubkey}
                Endpoint = {endpoint}
                AllowedIPs = {vpn_subnet}, 172.16.0.0/16, 192.168.0.0/16
                PersistentKeepalive = 25
                """
            # setting Peer End point is Optional due to all peers are in same netowrk

            output_path = "/tmp/CA_workspace/wg0.conf"
            with open(output_path, "w") as f:
                f.write(config)

            logging.info(f"[+] WireGuard config created at: {output_path}")

        except KeyError as e:
            logging.warning(f"[!] Missing key in response: {e}")
        except Exception as ex:
            logging.warning(f"[!] Error creating WireGuard config: {ex}")
        

    def Create_interface(self):
        wg_interface = "CA_workspace/wg0"  # Your WireGuard interface name

        try:
            logging.info(f"[+] Starting WireGuard interface...")
            try:
                subprocess.run(
                    ["sudo", "wg-quick", "up", f"/tmp/{wg_interface}.conf"],
                    check=True,
                    capture_output=True,
                    text=True
                )
            except subprocess.CalledProcessError as e:
                logging.warning("[!] WireGuard command failed:")
                logging.warning(f"STDOUT:\n{e.stdout}")
                logging.warning(f"STDERR:\n{e.stderr}")

            logging.info(f"[+] WireGuard interface is up. Press Ctrl+C to stop.")

            # Simulate running service (you can replace this with your actual logic)

        except subprocess.CalledProcessError as e:
            logging.warning(f"[!] WireGuard command failed: {e}")


    def setup_crypto(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # first32 bytes for AES and next 32 for HMAC
            salt=b'ztna_salt', 
            iterations=100000,
            backend=default_backend()
        )
        master_key = kdf.derive(password.encode('utf-8'))
        self.encryption_key = master_key[:32]
        self.hmac_key = master_key[32:]
    
    def create_packet(self):
        iv = os.urandom(16) # Generate a new IV for each packet

        packet_data = {
            'source_ip': self.config['source_ip'],
            'access_port': self.config['access_port'],
            'protocol': self.config['protocol'],
            'timestamp': int(time.time()),
            'message': 'SPA request from SDP Client',
            'resource_ip':self.config['resource_ip']
        }      
        if self.verbose:
            logging.info(f"\nPacket data:")
            pprint.pprint(packet_data)

        json_data = json.dumps(packet_data).encode()
        h = hmac.new(self.hmac_key, json_data, hashlib.sha256)
        hmac_digest = h.digest()
        
        if self.verbose:
            logging.info(f"\nHMAC digest (hex):")
            logging.info(hmac_digest.hex())
        
        # Combine data and HMAC
        final_data = json_data + hmac_digest

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(final_data) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        final_packet = iv + encrypted # the first 16 bits is the iv which will be extracted on server side
        
        if self.verbose:
            logging.info(f"\nEncrypted data (base64):")
            logging.info(base64.b64encode(final_packet).decode())
        
        return final_packet

    def send_keepalive(self):
        try:
            self.send_packet(is_keepalive=True)
            if self.verbose:
                logging.info(f"Keepalive packet sent to {self.config['server_ip']}:{self.config['server_port']}")
        except Exception as e:
            logging.warning(f"[!] Error sending keepalive packet: {str(e)}")
        finally:
            # Schedule next keepalive
            self.keepalive_timer = threading.Timer(
                self.keepalive_interval,
                self.send_keepalive
            )
            self.keepalive_timer.start()
    
    def send_wireguard_key(self, sock):
        try: 
            public_key = wireguard.get_public_key()
            
            if self.verbose:
                logging.info(f"WireGuard public key sent to the server: {public_key}")

            key_bytes = str(public_key).encode()
            sock.sendto(key_bytes, (self.config['server_ip'], self.config['server_port']))
            sock.settimeout(15)

            try:
                response, addr = sock.recvfrom(1024)
                if response:
                    logging.info(f"Server response to key: {response.decode()}")
                    self.Create_Conf(json.loads(response.decode()))
                    self.Create_interface()
                self.connection = 1

            except socket.timeout:
                logging.info(f"No response received after sending WireGuard key")

        except Exception as e:
            logging.warning(f"[!] Error sending WireGuard key: {e}")

    def send_packet(self, is_keepalive=False):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Open a UDP socket
            packet = self.create_packet() 

            sock.sendto(packet, (self.config['server_ip'], self.config['server_port']))

            if not is_keepalive:
                logging.info(f"SPA packet sent to {self.config['server_ip']}:{self.config['server_port']}")
            else:
                logging.info(f"sent a Keepalive packet")

            if self.verbose and not is_keepalive:
                logging.info(f"Requesting access to port: {self.config['access_port']}")
            
            # Only wait for response and send WireGuard key for initial packets, not keepalive
            if not is_keepalive:
                sock.settimeout(5)
                try:
                    response, addr = sock.recvfrom(1024)
                    
                    if response:
                        logging.info(response.decode())
                        # Only send WireGuard key for successful initial authentication
                        self.send_wireguard_key(sock)
                        return True  
                            
                except socket.timeout:
                    logging.info("No response received from server")
                    return False  
            
            return True  # For keepalive packets, assume success

        except Exception as e:
            logging.warning(f"[!] Error sending packet: {str(e)}")
            return False  # Failed
        finally:
            sock.close()

    def start_keepalive(self):
        # Start keepalive timer
        self.keepalive_timer = threading.Timer(
            self.keepalive_interval,
            self.send_keepalive
        )
        self.keepalive_timer.start()
        if self.verbose and self.connection:
            logging.info(f"Keepalive mechanism started (interval: {self.keepalive_interval} seconds)")
        elif self.connection:
            logging.info(f"Keepalive mechanism started")
        else :
            logging.info(f"No Wiregaurd key Recieved in Interval")

    def stop_keepalive(self):
        if self.keepalive_timer:
            self.keepalive_timer.cancel()
            logging.info(f"Keepalive mechanism stopped")

        # -----------------------------
    # WireGuard Handshake Monitoring
    # -----------------------------
    def monitor_handshake(self):
        """
        Background monitor that checks the latest WireGuard handshake every minute.
        If no handshake for > THRESHOLD seconds, the tunnel is removed.
        """
        logging.info(f"[+] Handshake monitor started for {WG_INTERFACE} (threshold: {THRESHOLD}s)")
        
        while True:
            try:
                # Check if interface exists
                result = subprocess.run(
                    ["sudo", "wg", "show", WG_INTERFACE, "dump"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )

                if result.returncode != 0:
                    logging.warning(f"[!] WireGuard not active: {result.stderr.strip()}")
                    time.sleep(60)
                    continue

                lines = result.stdout.strip().splitlines()
                if len(lines) < 2:
                    logging.warning("[!] No active peers on interface.")
                    time.sleep(60)
                    continue

                # Extract latest handshake timestamp
                peer_info = lines[1].split("\t")
                latest = int(peer_info[4]) if peer_info[4].isdigit() else 0
                now = int(time.time())
                age = now - latest if latest else -1

                logging.info(f"[monitor] Handshake age: {age}s")

                if latest == 0 or age > THRESHOLD:
                    logging.warning(f"[!] No handshake for >{THRESHOLD}s — cleaning up interface...")
                    pubkey = peer_info[0]
                    subprocess.run(
                        ["sudo", "wg", "set", WG_INTERFACE, "peer", pubkey, "remove"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    logging.warning(f"[!] Peer {pubkey} removed due to inactivity.")
                    break

            except Exception as e:
                logging.warning(f"[!] Handshake monitor error: {e}")

            time.sleep(60)  # check every minute


    def start_monitor_process(self):
        """
        Launches the stale-handshake monitor as a detached process.
        Survives SPA client termination.
        """
        logging.info("[+] Launching detached monitor process...")

        cmd = [
            sys.executable,
            self.monitor_script,
            self.interface,
            str(self.stale_timeout)
        ]

        # Pass verbose flag to monitor if enabled
        if self.verbose:
            cmd.append("-v")

        subprocess.Popen(
            ["nohup"] + cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )

        logging.info("[+] Monitor process started successfully (independent).")



def main():
    parser = argparse.ArgumentParser(
        description='SPA Client - Sends Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Request access to port 80 (TCP):
    python3 spa_client.py -A 80 -p 62201

  Request access to port 53 (UDP):
    python3 spa_client.py -A 53 -P udp -p 62201

  Request access to port 443 with verbose output:
    python3 spa_client.py -A 443 -p 62201 -v

  Specify source IP and keepalive interval:
    python3 spa_client.py -A 80 -s 192.168.1.100 -k 120 (for 2 minutes)

  Use custom config file:
    python3 spa_client.py -A 22 -p 62201 -c custom_config.json
''')
    parser.add_argument('-A', '--access', type=int,
                      help='Target port to request access to (overrides config file)')
    parser.add_argument('-p', '--port', type=int, default=62201,
                      help='Destination port to send SPA packet to (default: 62201)')
    parser.add_argument('-P', '--protocol', choices=['tcp', 'udp'], default='tcp',
                      help='Protocol to request access for (default: tcp)')
    parser.add_argument('-s', '--source-ip', type=str,
                      help='Override source IP address')
    parser.add_argument('-k', '--keepalive', type=int, default=240,
                      help='Keepalive interval in seconds (default: 240)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show verbose output including packet details')
    parser.add_argument('-c', '--config', default='client_config.json',
                      help='Path to config file (default: client_config.json)')
    args = parser.parse_args()

    client = SPAClient(config_file=args.config, access_port=args.access, 
                      server_port=args.port, protocol=args.protocol,
                      source_ip=args.source_ip, keepalive_interval=args.keepalive,
                      verbose=args.verbose)
    
    # Send initial packet and check if successful
    if client.send_packet():
        client.start_monitor_process()
        client.start_keepalive()  # Only start keepalive if initial packet was successful
        try:
            # Keep the script running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            client.stop_keepalive()
            logging.info(f"\nClient shutting down")
    else:
        logging.info("Failed to connect to server. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()