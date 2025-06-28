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
import hmac
import hashlib
import time
import threading
import base64
import argparse
import pprint
import os
import ipaddress

class SPAServer:
    def __init__(self, config_file='server_config.json', verbose=False, port=62201, daemon=False):
        self.verbose = verbose
        self.port = port
        self.daemon = daemon
        self.load_config(config_file)
        self.setup_logging()
        self.setup_crypto()
        self.socket = None
        self.running = True
        # Track received SPA packets
        self.spa_requests = {}
        # Override the values from config if specified
        if 'verbose' in self.config:
            self.verbose = self.config['verbose']
        if 'listen_port' in self.config:
            self.port = self.config['listen_port']
        if 'daemon' in self.config:
            self.daemon = self.config['daemon']

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file {config_file} not found")
            sys.exit(1)

    def setup_logging(self):
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level = logging.INFO
        handlers = []

        # Add file handler
        try:
            file_handler = logging.FileHandler(self.config['log_file'])
            file_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(file_handler)
        except Exception as e:
            print(f"Failed to set up file logger: {e}")

        # Add console handler if not daemon, or if verbose
        if self.verbose or not self.daemon:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(console_handler)

        # Configure root logger manually
        logging.getLogger().handlers = []  # Clear existing handlers
        logging.getLogger().setLevel(log_level)
        for handler in handlers:
            logging.getLogger().addHandler(handler)
    
    def setup_crypto(self, password=None):
        # Derive AES key from encryption key
        password = self.config['encryption_key'] # get the password from config file
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # first32 bytes for AES and next 32 for HMAC
            salt=b'ztna_salt', # Fixed salt for consistency
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
    
    def is_ip_allowed(self, ip):
        allowed_list =  self.config['allowed_ips']
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net in allowed_list:
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            return False
        except ValueError:
            return False
    
    def handle_packet(self, data, addr):
        try:
            if self.verbose:
                print(f"\nReceived packet from {addr[0]}:{addr[1]}")
                print(f"Raw data (base64): {base64.b64encode(data).decode()}")
            
            # Decrypt the packet
            decrypted, received_hmac = self.decrypt_packet(data)
            
            if self.verbose:
                print(f"Decrypted data: {decrypted}")
                print(f"HMAC from packet: {received_hmac.hex()}")
            
            # Verify HMAC
            if not self.verify_hmac(decrypted, received_hmac):
                logging.warning(f"Invalid HMAC from {addr[0]}")
                return
            
            # Parse the packet
            packet_data = json.loads(decrypted)
            
            if self.verbose:
                print("\nPacket contents:")
                pprint.pprint(packet_data)
            
            # Check if source IP is allowed
            if not self.is_ip_allowed(packet_data.get('source_ip')):
                logging.warning(f"Unauthorized IP {packet_data.get('source_ip')}")
                self.reply(addr, False)
                return
            
            # Check if protocol is allowed
            if 'allowed_protocols' in self.config:
                if packet_data.get('protocol') not in self.config['allowed_protocols']:
                    logging.warning(f"Unauthorized protocol {packet_data.get('protocol')}")
                    self.reply(addr, False)
                    return
            
            # Log the access request
            key = f"{addr[0]}:{packet_data.get('port', '')}:{packet_data.get('protocol', '')}" # example key = "192.168.1.5:22:tcp"
            self.spa_requests[key] = {
                'timestamp': time.time(),
                'data': packet_data
            }
            self.reply(addr,True)
            logging.info(f"Authorized SPA request: {key}")
            
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
            self.reply(addr, False)
            if self.verbose:
                import traceback
                traceback.print_exc()

    def recieve_key(self,addr):
        try:
            self.socket.settimeout(10)  # Wait max 10s for the key
            data, sender = self.socket.recvfrom(4096)
            try:
                key = data.decode().strip()
            except UnicodeDecodeError:
                return
            if key:
                logging.info(f"WireGuard public key received from {addr}: {key}")
            else:
                logging.warning(f"Invalid key format received from {addr}")

        except socket.timeout:
            logging.warning(f"No key received from {addr} within timeout")

        except Exception as e:
            logging.error(f"Error receiving key from {addr}: {str(e)}")

    def reply(self,addr,result):
        if result:
            self.socket.sendto('SPA Verification successfull'.encode(),addr)
            self.recieve_key(addr)
        else:
            self.socket.sendto('SPA Verification Failed'.encode(),addr)
        
        # pass
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('0.0.0.0', self.port)) # Change to the interface if needed
            logging.info(f"Server started on port {self.port}")
            logging.info(f"Listening on all interfaces (0.0.0.0)")
            
            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    if self.verbose:
                        logging.info(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")
                    self.handle_packet(data, addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Error processing packet: {str(e)}")
                    continue
        except KeyboardInterrupt:
            logging.info("Server shutting down")
        finally:
            self.cleanup()

    def signal_handler(self, signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        if self.socket:
            self.socket.close()
        sys.exit(0)

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
            print(f"Fork failed: {e}")
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
    main() 