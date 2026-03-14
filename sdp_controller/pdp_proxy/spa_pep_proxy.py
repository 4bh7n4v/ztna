"""
spa_pep_proxy.py — Front-End PEP Proxy for Zero Trust SPA Architecture
=======================================================================
Sits between the untrusted network and the PDP (SPAServer).

Responsibilities:
  1. FILTER  — Drop malformed / too-short packets before the PDP ever sees them.
  2. RELAY   — Forward only structurally valid packets to the PDP's UDP port.
  3. RATE-LIMIT — Enforce the 10 s–120 s keepalive window; blacklist abusers.

Topology:
  [Client] --UDP--> [PEP Proxy :62200] --UDP--> [PDP SPAServer :62201]
                          |
                    (drops / blacklists)

The proxy is transparent: replies from the PDP are forwarded back to the
original client, so no changes are needed on the client or PDP side.

Usage:
  python3 spa_pep_proxy.py [--listen-port 62200] [--pdp-host 127.0.0.1]
                            [--pdp-port 62201] [--verbose]
"""

import socket
import threading
import time
import logging
import argparse
import json
import base64
import struct
from collections import defaultdict, deque

# ---------------------------------------------------------------------------
# Constants — tune to match your deployment
# ---------------------------------------------------------------------------

# Minimum packet size that the PDP will accept (IV=16 + HMAC=32 = 48 bytes)
MIN_PACKET_SIZE = 44

# Maximum sane UDP payload (avoid processing giant junk)
MAX_PACKET_SIZE = 4096

# --- Rate-limiting parameters ---
# Minimum seconds between legitimate packets from ONE source IP.
# Legit clients send keepalives every 10–120 s, so anything faster is abuse.
RATE_LIMIT_MIN_INTERVAL = 9        # seconds — slightly under 10 s keepalive floor
RATE_LIMIT_BURST_COUNT  = 3        # allow a tiny burst at startup (SPA + WG handshake)
RATE_LIMIT_BURST_WINDOW = 15       # seconds in which the burst is measured

# How long a blacklisted IP is blocked
BLACKLIST_DURATION = 300           # 5 minutes

# How often the background janitor cleans stale state (seconds)
JANITOR_INTERVAL = 60

# Reply payload sent back to blocked/dropped senders (deliberately vague)
SILENT_DROP = False   # True  = no reply at all (stealthier)
                      # False = send a small error reply (easier to debug)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool):
    fmt = "%(asctime)s [PEP] %(levelname)-8s %(message)s"
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format=fmt, level=level)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Per-source-IP rate limiter with burst allowance and auto-blacklisting.

    Algorithm:
      - Maintain a deque of recent packet timestamps per IP.
      - If the deque fills up faster than RATE_LIMIT_MIN_INTERVAL warrants,
        increment a violation counter.
      - After 3 consecutive violations, blacklist the IP.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {ip: deque of float timestamps}
        self._history: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=RATE_LIMIT_BURST_COUNT + 5)
        )
        # {ip: violation_count}
        self._violations: dict[str, int] = defaultdict(int)
        # {ip: blacklist_expiry_timestamp}
        self._blacklist: dict[str, float] = {}

    # ------------------------------------------------------------------ #
    def is_allowed(self, ip: str) -> tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        Call this for every incoming packet BEFORE forwarding.
        """
        with self._lock:
            now = time.time()

            # 1. Check blacklist
            if ip in self._blacklist:
                if now < self._blacklist[ip]:
                    remaining = int(self._blacklist[ip] - now)
                    return False, f"blacklisted ({remaining}s remaining)"
                else:
                    # Blacklist expired — give a clean slate
                    del self._blacklist[ip]
                    self._violations[ip] = 0
                    self._history[ip].clear()

            # 2. Record this packet
            hist = self._history[ip]
            hist.append(now)

            # 3. Burst check: if RATE_LIMIT_BURST_COUNT+1 packets arrived
            #    within RATE_LIMIT_BURST_WINDOW seconds, that's a burst violation
            if len(hist) > RATE_LIMIT_BURST_COUNT:
                window_start = now - RATE_LIMIT_BURST_WINDOW
                recent = [t for t in hist if t >= window_start]
                if len(recent) > RATE_LIMIT_BURST_COUNT:
                    self._violations[ip] += 1
                    logging.warning(
                        f"[RateLimit] {ip} burst violation #{self._violations[ip]} "
                        f"({len(recent)} pkts in {RATE_LIMIT_BURST_WINDOW}s)"
                    )
                    if self._violations[ip] >= 3:
                        self._blacklist[ip] = now + BLACKLIST_DURATION
                        logging.warning(
                            f"[RateLimit] {ip} BLACKLISTED for {BLACKLIST_DURATION}s"
                        )
                        return False, "auto-blacklisted after repeated violations"
                    return False, "burst rate exceeded"

            # 4. Minimum-interval check (catches steady drip floods too)
            if len(hist) >= 2:
                gap = hist[-1] - hist[-2]
                if gap < RATE_LIMIT_MIN_INTERVAL:
                    self._violations[ip] += 1
                    logging.warning(
                        f"[RateLimit] {ip} too-fast violation #{self._violations[ip]} "
                        f"(gap={gap:.2f}s < {RATE_LIMIT_MIN_INTERVAL}s)"
                    )
                    if self._violations[ip] >= 3:
                        self._blacklist[ip] = now + BLACKLIST_DURATION
                        logging.warning(
                            f"[RateLimit] {ip} BLACKLISTED for {BLACKLIST_DURATION}s"
                        )
                        return False, "auto-blacklisted after repeated violations"
                    return False, "packets arriving too fast"

            # Looks fine — reset violation streak on a clean packet
            self._violations[ip] = 0
            return True, "ok"

    # ------------------------------------------------------------------ #
    def manual_blacklist(self, ip: str, duration: int = BLACKLIST_DURATION):
        with self._lock:
            self._blacklist[ip] = time.time() + duration
            logging.warning(f"[RateLimit] {ip} manually blacklisted for {duration}s")

    def manual_unblock(self, ip: str):
        with self._lock:
            self._blacklist.pop(ip, None)
            self._violations[ip] = 0
            self._history[ip].clear()
            logging.info(f"[RateLimit] {ip} manually unblocked")

    def purge_stale(self):
        """Remove entries for IPs that haven't been seen in a long while."""
        cutoff = time.time() - (BLACKLIST_DURATION * 2)
        with self._lock:
            stale = [
                ip for ip, hist in self._history.items()
                if hist and hist[-1] < cutoff
                and ip not in self._blacklist
            ]
            for ip in stale:
                del self._history[ip]
                self._violations.pop(ip, None)
            if stale:
                logging.debug(f"[Janitor] Purged {len(stale)} stale rate-limit entries")

    def stats(self) -> dict:
        with self._lock:
            now = time.time()
            return {
                "tracked_ips": len(self._history),
                "blacklisted": {
                    ip: int(exp - now)
                    for ip, exp in self._blacklist.items()
                    if exp > now
                },
                "violation_counts": dict(self._violations),
            }


# ---------------------------------------------------------------------------
# Packet filter
# ---------------------------------------------------------------------------

class PacketFilter:
    """
    Stateless structural checks on raw UDP payloads.

    Checks performed (in order, cheapest first):
      1. Size bounds
      2. Non-zero IV (first 16 bytes must not be all-zero)
      3. Padding sanity (last byte of ciphertext must be 1–16 for PKCS7)
    """

    @staticmethod
    def inspect(data: bytes) -> tuple[bool, str]:
        # --- 1. Size bounds ---
        if len(data) < MIN_PACKET_SIZE:
            return False, f"too short ({len(data)} < {MIN_PACKET_SIZE} bytes)"
        if len(data) > MAX_PACKET_SIZE:
            return False, f"too long ({len(data)} > {MAX_PACKET_SIZE} bytes)"

        # --- 2. IV must not be all-zero (trivially weak / likely junk) ---
        iv = data[:16]
        if iv == b'\x00' * 16:
            return False, "all-zero IV (likely junk)"

        # --- 3. Ciphertext length must be a multiple of AES block size (16 bytes)
        #        IV (16) is stripped; remainder must be ≥32 bytes and block-aligned ---
        ciphertext = data[16:]
        if len(ciphertext) < 32:
            return False, "ciphertext too short after IV"
        if len(ciphertext) % 16 != 0:
            return False, f"ciphertext length {len(ciphertext)} not AES-block-aligned"

        return True, "ok"

    @staticmethod
    def inspect(data: bytes) -> tuple[bool, str]:

        # WireGuard public key bypass — 44 byte base64, skip all crypto checks
        if 40 <= len(data) <= 48:
            try:
                decoded = base64.b64decode(data.strip())
                if len(decoded) == 32:
                    return True, "wireguard-key"
            except Exception:
                pass

        # Size bounds
        if len(data) < MIN_PACKET_SIZE:
            return False, f"too short ({len(data)} < {MIN_PACKET_SIZE} bytes)"
        if len(data) > MAX_PACKET_SIZE:
            return False, f"too long ({len(data)} > {MAX_PACKET_SIZE} bytes)"

        # IV must not be all-zero
        iv = data[:16]
        if iv == b'\x00' * 16:
            return False, "all-zero IV (likely junk)"

        # Ciphertext length check
        ciphertext = data[16:]
        if len(ciphertext) < 32:
            return False, "ciphertext too short after IV"
        if len(ciphertext) % 16 != 0:
            return False, f"ciphertext length {len(ciphertext)} not AES-block-aligned"

        return True, "ok"
    # ```

# ---

# ## Also Fix RateLimiter — WireGuard Key Sent Too Fast

# The WireGuard key is sent **immediately after** the SPA packet — gap is ~2ms which triggers:
# ```
# [RateLimit] packets arriving too fast (gap=0.002s < 9s)


# ---------------------------------------------------------------------------
# Relay (proxy core)
# ---------------------------------------------------------------------------

class PEPProxy:
    """
    UDP proxy: Client → PEP → PDP, with filtering and rate-limiting.

    A small per-client socket is created on first contact so replies from
    the PDP are routed back to the correct client.
    """

    def __init__(
        self,
        listen_host: str = "10.0.0.10",    # FrontProxy eth0
        listen_port: int = 62201,           # must match PORT_SPA
        pdp_host: str    = "10.0.3.100",   # Controller eth1 direct link
        pdp_port: int    = 62201,           # SDP Controller port
        mgmt_ip: str     = "10.0.3.10",    # FrontProxy eth1 direct link
        verbose: bool    = False,
    ):
        self.listen_addr = (listen_host, listen_port)
        self.pdp_addr    = (pdp_host, pdp_port)
        self.pdp_host    = pdp_host         # ← ADD THIS
        self.pdp_port    = pdp_port         # ← ADD THIS
        self.mgmt_ip     = mgmt_ip
        self.verbose     = verbose
        self.rate_limiter = RateLimiter()
        self.pkt_filter   = PacketFilter()
        self._relay_sockets: dict[tuple, socket.socket] = {}
        self._relay_lock  = threading.Lock()
        self._running     = True
        self._stats = {
            "received":      0,
            "forwarded":     0,
            "dropped_filter": 0,
            "dropped_rate":   0,
        }
        ryu_relay_thread = threading.Thread(
            target=self._forward_to_ryu,
            daemon=True
        )
        ryu_relay_thread.start()
        logging.info('[Relay] SDN relay thread started')
        
    # ------------------------------------------------------------------ #
    def _get_or_create_relay(self, client_addr: tuple) -> socket.socket:
            """Return (or create) a dedicated UDP socket for this client→PDP relay."""
            with self._relay_lock:
                if client_addr not in self._relay_sockets:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
                    # BIND to Management IP (eth1) to ensure traffic stays off s1
                    try:
                        # Uses self.mgmt_ip (10.0.2.10) to talk to the PDP
                        s.bind((self.pdp_host.rsplit('.', 1)[0] + '.10', 0)) 
                    except Exception as e:
                        logging.error(f"[Relay] Failed to bind to mgmt interface: {e}")

                    s.settimeout(2.0)
                    self._relay_sockets[client_addr] = s

                    # MUST KEEP THIS: This thread sends PDP replies back to the Client
                    t = threading.Thread(
                        target=self._pdp_reply_listener,
                        args=(s, client_addr),
                        daemon=True,
                    )
                    t.start()
                    logging.debug(f"[Relay] New relay socket (mgmt bound) for {client_addr}")
                
                return self._relay_sockets[client_addr]

    def _pdp_reply_listener(self, relay_sock: socket.socket, client_addr: tuple):
        """Background thread: forward PDP replies back to the client."""
        while self._running:
            try:
                data, _ = relay_sock.recvfrom(MAX_PACKET_SIZE)
                self._front_sock.sendto(data, client_addr)
                if self.verbose:
                    logging.debug(
                        f"[Relay] PDP→Client {client_addr}: {len(data)} bytes"
                    )
            except socket.timeout:
                continue
            except OSError:
                break

    # Add this to spa_pep_proxy.py
    def _forward_to_ryu(self):
        """
        Listen on management interface for SDN commands from SDP Controller
        Forward them to Ryu via S1 (src=10.0.0.10, dst=7777)
        """
        mgmt_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mgmt_sock.bind(('10.0.3.10', 7777))
        logging.info('[Relay] Listening for SDN commands on 10.0.3.10:7777')

        while self._running:
            try:
                data, addr = mgmt_sock.recvfrom(4096)
                logging.debug('[Relay] SDN command from Controller: %s', data)

                # Forward to Ryu via S1 using FrontProxy eth0
                ryu_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ryu_sock.bind(('10.0.0.10', 0))   # bind to S1-facing interface
                ryu_sock.sendto(data, ('10.0.0.1', 7777))  # Ryu sees src=10.0.0.10
                ryu_sock.close()
                logging.info('[Relay] SDN command forwarded to Ryu via S1')

            except Exception as e:
                logging.error('[Relay] SDN forward error: %s', e)

        mgmt_sock.close()

    # ------------------------------------------------------------------ #
    def _handle_incoming(self, data: bytes, client_addr: tuple):
        client_ip = client_addr[0]
        self._stats["received"] += 1

        # ── 1. Structural filter ──────────────────────────────────────
        ok, reason = self.pkt_filter.inspect(data)
        if not ok:
            self._stats["dropped_filter"] += 1
            logging.warning(f"[Filter] DROPPED {client_ip}:{client_addr[1]} — {reason}")
            if not SILENT_DROP:
                try:
                    self._front_sock.sendto(b"SPA Verification Failed", client_addr)
                except Exception:
                    pass
            return

        # ── 2. Rate limiter — skip for WireGuard key packets ──────────
        if reason != "wireguard-key":   # ← bypass rate limit for WG key
            allowed, rl_reason = self.rate_limiter.is_allowed(client_ip)
            if not allowed:
                self._stats["dropped_rate"] += 1
                logging.warning(f"[RateLimit] DROPPED {client_ip}:{client_addr[1]} — {rl_reason}")
                if not SILENT_DROP:
                    try:
                        self._front_sock.sendto(b"SPA Verification Failed", client_addr)
                    except Exception:
                        pass
                return

        # ── 3. Forward to PDP ─────────────────────────────────────────
        try:
            relay = self._get_or_create_relay(client_addr)
            relay.sendto(data, self.pdp_addr)
            self._stats["forwarded"] += 1
            if self.verbose:
                logging.debug(
                    f"[Relay] Client {client_ip}:{client_addr[1]} "
                    f"→ PDP {self.pdp_addr}: {len(data)} bytes"
                )
        except Exception as e:
            logging.error(f"[Relay] Forward error for {client_ip}: {e}")

    # ------------------------------------------------------------------ #
    def _janitor(self):
        """Background thread: periodic housekeeping."""
        while self._running:
            time.sleep(JANITOR_INTERVAL)
            self.rate_limiter.purge_stale()

            # Log current stats
            s = self._stats
            logging.info(
                f"[Stats] recv={s['received']} fwd={s['forwarded']} "
                f"drop_filter={s['dropped_filter']} drop_rate={s['dropped_rate']}"
            )
            bl = self.rate_limiter.stats()["blacklisted"]
            if bl:
                logging.info(f"[Stats] Blacklisted IPs: {bl}")

            # Prune dead relay sockets
            with self._relay_lock:
                dead = [
                    addr for addr, sock in self._relay_sockets.items()
                    if sock.fileno() == -1
                ]
                for addr in dead:
                    del self._relay_sockets[addr]

    # ------------------------------------------------------------------ #
    def start(self):
        self._front_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._front_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._front_sock.bind(self.listen_addr)

        logging.info(
            f"[PEP] Proxy listening on {self.listen_addr[0]}:{self.listen_addr[1]} "
            f"→ PDP at {self.pdp_addr[0]}:{self.pdp_addr[1]}"
        )
        logging.info(
            f"[PEP] Filter: min_pkt={MIN_PACKET_SIZE}B  "
            f"Rate: min_interval={RATE_LIMIT_MIN_INTERVAL}s  "
            f"burst={RATE_LIMIT_BURST_COUNT}/{RATE_LIMIT_BURST_WINDOW}s  "
            f"blacklist={BLACKLIST_DURATION}s"
        )

        janitor = threading.Thread(target=self._janitor, daemon=True)
        janitor.start()

        try:
            while self._running:
                try:
                    data, addr = self._front_sock.recvfrom(MAX_PACKET_SIZE)
                    # Handle each packet in the main thread (fast path).
                    # For high-throughput, swap to a thread-pool here.
                    self._handle_incoming(data, addr)
                except OSError:
                    break
        except KeyboardInterrupt:
            logging.info("[PEP] KeyboardInterrupt — shutting down.")
        finally:
            self._running = False
            self._front_sock.close()
            with self._relay_lock:
                for s in self._relay_sockets.values():
                    try:
                        s.close()
                    except Exception:
                        pass
            logging.info("[PEP] Shutdown complete.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SPA PEP Proxy — Front-End Filter for Zero Trust SPA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: listen :62200, forward to localhost:62201
  python3 spa_pep_proxy.py

  # Custom PDP location, verbose
  python3 spa_pep_proxy.py --pdp-host 10.0.0.5 --pdp-port 62201 -v

  # Listen on a specific interface
  python3 spa_pep_proxy.py --listen-host 192.168.1.10 --listen-port 62200
""",
    )
    parser.add_argument("--listen-host", default="0.0.0.0",
                        help="Interface to listen on (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=62200,
                        help="UDP port to accept client packets (default: 62200)")
    parser.add_argument("--pdp-host", default="127.0.0.1",
                        help="PDP (SPAServer) IP address (default: 127.0.0.1)")
    parser.add_argument("--pdp-port", type=int, default=62201,
                        help="PDP (SPAServer) UDP port (default: 62201)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug-level logging")
    args = parser.parse_args()

    setup_logging(args.verbose)

    proxy = PEPProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        pdp_host=args.pdp_host,
        pdp_port=args.pdp_port,
        verbose=args.verbose,
    )
    proxy.start()


if __name__ == "__main__":
    main()
