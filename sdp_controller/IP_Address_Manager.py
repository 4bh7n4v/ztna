import sqlite3
import os
import logging

DB_FILE = "ipam.db"

# ===============================
# Expected Schemas
# ===============================

EXPECTED_SCHEMAS = {
    "gateways": {
        "gateway_id", "name", "vpn_subnet", "gateway_vpn_ip",
        "wireguard_interface", "listen_port", "public_key",
        "ssh_user", "ssh_host", "ssh_port", "ssh_key_path",
        "status", "created_at"
    },
    "devices": {
        "device_id", "public_key", "public_ip",
        "role", "status", "created_at"
    },
    "vpn_leases": {
        "lease_id", "device_id", "gateway_id", "vpn_ip",
        "status", "lease_start", "last_seen", "lease_expiry",
        "revoked_at", "revoke_reason"  
    },
    "audit_logs": {
        "log_id", "event_type", "device_id",
        "gateway_id", "details", "created_at"
    }
}


# ===============================
# Utility Functions
# ===============================

def get_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    return conn


def get_table_columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return {row[1] for row in cursor.fetchall()}


def drop_table(cursor, table_name):
    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
    logging.info(f"[R&D MODE] Dropped table: {table_name}")


# ===============================
# Table Creation Functions
# ===============================

def create_gateways(cursor):
    cursor.execute("""
        CREATE TABLE gateways (
            gateway_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            vpn_subnet TEXT NOT NULL,
            gateway_vpn_ip TEXT NOT NULL,
            wireguard_interface TEXT NOT NULL,
            listen_port INTEGER NOT NULL,
            public_key TEXT,
            ssh_user TEXT,
            ssh_host TEXT,
            ssh_port INTEGER DEFAULT 22,
            ssh_key_path TEXT,
            status TEXT DEFAULT 'offline',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


def create_devices(cursor):
    cursor.execute("""
        CREATE TABLE devices (
            device_id TEXT PRIMARY KEY,
            public_key TEXT UNIQUE NOT NULL,
            public_ip TEXT,
            role TEXT,
            status TEXT DEFAULT 'offline',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


def create_vpn_leases(cursor):
    cursor.execute("""
        CREATE TABLE vpn_leases (
            lease_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id     TEXT NOT NULL,
            gateway_id    TEXT NOT NULL,
            vpn_ip        TEXT NOT NULL,
            status        TEXT DEFAULT 'active',
            lease_start   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen     TIMESTAMP,
            lease_expiry  TIMESTAMP,
            revoked_at    REAL,        -- ← add this
            revoke_reason TEXT,        -- ← add this

            UNIQUE(vpn_ip),
            UNIQUE(device_id),

            FOREIGN KEY(device_id)
                REFERENCES devices(device_id)
                ON DELETE CASCADE,

            FOREIGN KEY(gateway_id)
                REFERENCES gateways(gateway_id)
                ON DELETE CASCADE
        )
    """)


def create_audit_logs(cursor):
    cursor.execute("""
        CREATE TABLE audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            device_id TEXT,
            gateway_id TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


# ===============================
# Main Initialization
# ===============================

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    TABLE_CREATORS = {
        "gateways": create_gateways,
        "devices": create_devices,
        "vpn_leases": create_vpn_leases,
        "audit_logs": create_audit_logs
    }

    for table_name, create_function in TABLE_CREATORS.items():

        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name=?
        """, (table_name,))
        table_exists = cursor.fetchone()

        if table_exists:
            existing_columns = get_table_columns(cursor, table_name)

            if existing_columns != EXPECTED_SCHEMAS[table_name]:
                logging.info(f"[R&D MODE] Schema mismatch detected in {table_name}")
                drop_table(cursor, table_name)
                create_function(cursor)
                logging.info(f"[R&D MODE] Recreated table: {table_name}")
            else:
                logging.info(f"[OK] {table_name} schema valid")
        else:
            create_function(cursor)
            logging.info(f"[INIT] Created table: {table_name}")

    conn.commit()
    conn.close()

    logging.info("IPAM database ready.")