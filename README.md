# ZTNA - Zero Trust Network Access with Single Packet Authorization

A secure Zero Trust Network Access (ZTNA) implementation featuring Single Packet Authorization (SPA) and WireGuard integration for secure remote access to network resources.

## Overview

This project implements a Zero Trust Network Access solution that combines Single Packet Authorization (SPA) with WireGuard VPN technology to provide secure, authenticated access to network resources. The system consists of three main components:

- **SDP Client**: Initiates secure connections and handles authentication
- **SDP Controller**: Manages access control and authorization
- **SDP Gateway**: Provides secure network access (placeholder for future implementation)

## Features

- **Single Packet Authorization (SPA)**: Secure authentication using encrypted UDP packets
- **WireGuard Integration**: Modern VPN technology for secure tunneling
- **IP-based Access Control**: Configurable IP whitelisting
- **Protocol Filtering**: Support for TCP/UDP protocol restrictions
- **Keepalive Support**: Maintains persistent connections
- **Comprehensive Logging**: Detailed audit trails and debugging information
- **Cryptographic Security**: AES-256 encryption with HMAC authentication

## Architecture

```
┌─────────────┐    SPA Packet    ┌─────────────┐    WireGuard    ┌─────────────┐
│ SDP Client  │ ────────────────► │ SDP Controller │ ──────────────► │ SDP Gateway  │
│             │                   │             │                   │             │
│ - Auth      │                   │ - Access    │                   │ - Network   │
│ - Encryption│                   │ - Control   │                   │ - Routing   │
│ - WireGuard │                   │ - Logging   │                   │ - Security  │
└─────────────┘                   └─────────────┘                   └─────────────┘
```

## Components

### SDP Client (`sdp_client/`)

The client component responsible for:
- Generating and sending SPA packets
- Managing WireGuard key exchange
- Handling keepalive connections
- Configuration management

**Key Files:**
- `spa_client.py`: Main client implementation
- `client_config.json`: Client configuration
- `wireguard.py`: WireGuard integration utilities

### SDP Controller (`sdp_controller/`)

The server component responsible for:
- Processing SPA authentication requests
- Managing access control policies
- Logging and audit trails
- WireGuard key management

**Key Files:**
- `spa_server.py`: Main server implementation
- `server_config.json`: Server configuration
- `spa_server.log`: Server logs

### SDP Gateway (`sdp_gateway/`)

Future component for network gateway functionality (currently placeholder).

## Installation

### Prerequisites

- Python 3.7+
- WireGuard tools
- Required Python packages (see requirements.txt)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd ztna
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure WireGuard:
```bash
# Generate WireGuard keys
wg genkey | tee privatekey | wg pubkey > publickey
```

4. Configure client and server:
   - Edit `sdp_client/client_config.json`
   - Edit `sdp_controller/server_config.json`

## Configuration

### Client Configuration (`client_config.json`)

```json
{
    "server_ip": "192.168.1.100",
    "server_port": 62201,
    "source_ip": "192.168.1.50",
    "access_port": 22,
    "protocol": "tcp",
    "resource_ip": "192.168.1.200",
    "encryption_key": "your-secure-key-here",
    "keepalive_interval": 240,
    "verbose": false
}
```

### Server Configuration (`server_config.json`)

```json
{
    "listen_port": 62201,
    "encryption_key": "your-secure-key-here",
    "allowed_ips": ["192.168.1.0/24", "10.0.0.0/8"],
    "allowed_protocols": ["tcp", "udp"],
    "log_file": "spa_server.log",
    "verbose": false,
    "daemon": false
}
```

## Usage

### Starting the Server

```bash
cd sdp_controller
python spa_server.py --config server_config.json --verbose
```

### Starting the Client

```bash
cd sdp_client
python spa_client.py --config client_config.json --verbose
```

### Command Line Options

**Server Options:**
- `--config`: Configuration file path
- `--verbose`: Enable verbose logging
- `--port`: Listen port
- `--daemon`: Run as daemon

**Client Options:**
- `--config`: Configuration file path
- `--verbose`: Enable verbose logging
- `--access-port`: Target port for access
- `--protocol`: Protocol (tcp/udp)
- `--source-ip`: Source IP address

## Security Features

### Single Packet Authorization (SPA)

- **Encryption**: AES-256-CBC encryption
- **Authentication**: HMAC-SHA256 for packet integrity
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Salt**: Fixed salt for consistency

### Access Control

- **IP Whitelisting**: Configurable IP ranges
- **Protocol Filtering**: TCP/UDP protocol restrictions
- **Time-based Authorization**: Timestamp validation
- **Rate Limiting**: Built-in request tracking

### WireGuard Integration

- **Key Exchange**: Secure public key transmission
- **Tunnel Management**: Automatic tunnel establishment
- **Key Rotation**: Support for key updates

## Logging

The system provides comprehensive logging:

- **Access Logs**: All authentication attempts
- **Security Events**: Failed authentication, unauthorized access
- **Debug Information**: Detailed packet analysis (verbose mode)
- **Audit Trails**: Complete request history

## Development

### Project Structure

```
ztna/
├── sdp_client/
│   ├── spa_client.py
│   ├── client_config.json
│   ├── wireguard.py
│   └── __pycache__/
├── sdp_controller/
│   ├── spa_server.py
│   ├── server_config.json
│   └── spa_server.log
├── sdp_gateway/
├── test.py
└── README.md
```

### Testing

Run the basic connectivity test:
```bash
python test.py
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Considerations

- **Key Management**: Store encryption keys securely
- **Network Security**: Use firewalls to restrict access
- **Logging**: Monitor logs for suspicious activity
- **Updates**: Keep dependencies updated
- **Configuration**: Review and harden configurations

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the repository
- Check the logs for debugging information
- Review the configuration files
