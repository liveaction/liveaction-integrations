import os
import time
import requests
from urllib.parse import urljoin
from datetime import datetime, timezone
from helper.clickhouse import connect_with_tls

# ---------------------------
# CONFIG
# ---------------------------
BAM_BASE   = os.getenv("BAM_BASE", "https://bam.example.com")
USERNAME   = os.getenv("BAM_USER", "apiuser")
PASSWORD   = os.getenv("BAM_PASS", "apipassword")
CIDR       = os.getenv("BAM_CIDR", "10.42.0.0/24")
VERIFY_TLS = os.getenv("BAM_VERIFY_TLS", "false").lower() == "true"
PAGE_SIZE  = int(os.getenv("PAGE_SIZE", "1000"))

import os
import clickhouse_connect

# ClickHouse connection (add TLS knobs)
CH_HOST        = os.getenv("CH_HOST", "localhost")
CH_PORT        = int(os.getenv("CH_PORT", "8123"))
CH_USER        = os.getenv("CH_USER", "default")
CH_PASS        = os.getenv("CH_PASS", "")
CH_DB          = os.getenv("CH_DB", "netops")
CH_TABLE       = os.getenv("CH_TABLE", "ipam_devices")

# NEW: TLS-related
CH_SECURE      = os.getenv("CH_SECURE", "false").lower() == "true"  # HTTPS on/off
# IMPORTANT: set to False to ignore server cert validation (self-signed etc.)
CH_VERIFY_ENV  = os.getenv("CH_VERIFY", "true").lower()              # "true"|"false"|"/path/to/ca.pem"
CH_VERIFY      = (False if CH_VERIFY_ENV == "false"
                  else (True if CH_VERIFY_ENV == "true" else CH_VERIFY_ENV))  # str path or bool

# Optional mTLS (client auth)
CH_CLIENT_CERT = os.getenv("CH_CLIENT_CERT")  # path to client cert (PEM)
CH_CLIENT_KEY  = os.getenv("CH_CLIENT_KEY")   # path to client key (PEM)

# ---------------------------
# BAM REST helpers
# ---------------------------
REST = "/Services/REST/v1/"
HEADERS = {"Content-Type": "application/json"}

def bam_login():
    r = requests.post(urljoin(BAM_BASE, REST + "login"),
                      json={"username": USERNAME, "password": PASSWORD},
                      verify=VERIFY_TLS, headers=HEADERS)
    r.raise_for_status()
    token = r.text.strip().strip('"')
    return {"Authorization": token, "Content-Type": "application/json"}

def props_to_dict(prop_str):
    out = {}
    if not prop_str:
        return out
    for kv in prop_str.split("|"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k] = v
    return out

def get_network_entity(auth_headers, cidr):
    r = requests.get(urljoin(BAM_BASE, REST + "getIPRangedByCIDR"),
                     params={"cidr": cidr, "type": "IP4Network"},
                     headers=auth_headers, verify=VERIFY_TLS)
    r.raise_for_status()
    return r.json()

def get_entities(auth_headers, parent_id, etype, start=0, count=1000):
    r = requests.get(urljoin(BAM_BASE, REST + "getEntities"),
                     params={"parentId": parent_id, "type": etype, "start": start, "count": count},
                     headers=auth_headers, verify=VERIFY_TLS)
    r.raise_for_status()
    return r.json()

def get_linked_entities(auth_headers, entity_id, etype, start=0, count=10):
    r = requests.get(urljoin(BAM_BASE, REST + "getLinkedEntities"),
                     params={"entityId": entity_id, "type": etype, "start": start, "count": count},
                     headers=auth_headers, verify=VERIFY_TLS)
    r.raise_for_status()
    return r.json()

def safe_get_absolute_name(entity):
    props = props_to_dict(entity.get("properties", ""))
    return props.get("absoluteName") or entity.get("name") or ""

# ---------------------------
# ClickHouse helpers
# ---------------------------

def ch_client():
    # clickhouse-connect supports these SSL options over HTTP(S)
    # secure=True -> HTTPS; verify accepts bool or CA bundle path; client_cert/key for mTLS
    return clickhouse_connect.get_client(
        host=CH_HOST,
        port=CH_PORT,
        username=CH_USER,
        password=CH_PASS,
        database=CH_DB,
        secure=CH_SECURE,
        verify=CH_VERIFY,              # bool or path
        client_cert=CH_CLIENT_CERT,    # optional
        client_key=CH_CLIENT_KEY       # optional
    )


DDL = f"""
CREATE DATABASE IF NOT EXISTS {CH_DB};
CREATE TABLE IF NOT EXISTS {CH_DB}.{CH_TABLE}
(
    network_cidr     String,
    ip               String,
    hostname         String,
    fqdn             String,
    mac              String,
    state            LowCardinality(String),
    ip_version       LowCardinality(String),
    ptr_record       String,
    bam_network_id   UInt64,
    bam_ip_entity_id UInt64,
    source_system    LowCardinality(String),
    tenant           LowCardinality(String),
    document         String,
    snapshot_at      DateTime64(3, 'UTC'),
    _ingested_at     DateTime64(3, 'UTC'),
    _version         UInt64
)
ENGINE = ReplacingMergeTree(_version)
PARTITION BY toYYYYMM(snapshot_at)
ORDER BY (network_cidr, ip);
"""

def ch_init():
    client = ch_client()
    # run may contain multiple statements
    for stmt in [s.strip() for s in DDL.split(";") if s.strip()]:
        client.command(stmt)

def ch_insert(rows):
    if not rows:
        return
    client = ch_client()
    cols = [
        "network_cidr","ip","hostname","fqdn","mac","state","ip_version","ptr_record",
        "bam_network_id","bam_ip_entity_id","source_system","tenant","document",
        "snapshot_at","_ingested_at","_version"
    ]
    client.insert(f"{CH_DB}.{CH_TABLE}", rows, column_names=cols)

# ---------------------------
# Main pipeline
# ---------------------------
def build_document(row):
    # LLM-friendly, readable, denormalized text blob
    parts = [
        f"Device hostname: {row.get('hostname') or ''}",
        f"FQDN: {row.get('fqdn') or ''}",
        f"IP: {row.get('ip')}",
        f"MAC: {row.get('mac') or ''}",
        f"State: {row.get('state') or ''}",
        f"PTR: {row.get('ptr_record') or ''}",
        f"Network: {row.get('network_cidr')}",
        f"Source: {row.get('source_system')}",
        f"Tenant: {row.get('tenant') or ''}",
    ]
    return " | ".join(parts).strip(" |")

def run():
    snapshot_at = datetime.now(timezone.utc)
    ingested_at = snapshot_at
    version = int(snapshot_at.timestamp() * 1000)  # ms since epoch

    auth = bam_login()
    ipnet = get_network_entity(auth, CIDR)
    net_id = ipnet["id"]
    network_cidr = CIDR

    # Prepare ClickHouse (idempotent)
    ch_init()

    start = 0
    batch = []
    SOURCE = "BlueCat BAM"
    TENANT = ""  # set if you segregate envs

    while True:
        ip_addrs = get_entities(auth, net_id, "IP4Address", start=start, count=PAGE_SIZE)
        if not ip_addrs:
            break

        for ip_ent in ip_addrs:
            ip_props = props_to_dict(ip_ent.get("properties", ""))
            address = ip_props.get("address") or ip_ent.get("name") or ""
            state   = ip_props.get("state", "")
            mac     = ip_props.get("macAddress", "")

            # Try linked HostRecord (for device identity/FQDN).
            host_records = get_linked_entities(auth, ip_ent["id"], "HostRecord", start=0, count=1)
            fqdn = ""
            hostname = ""
            if host_records:
                fqdn = safe_get_absolute_name(host_records[0])
                hostname = host_records[0].get("name", "")  # left label

            # PTR (reverse record) if present
            ptr_records = get_linked_entities(auth, ip_ent["id"], "PTRRecord", start=0, count=1)
            ptr = safe_get_absolute_name(ptr_records[0]) if ptr_records else ""

            # If no hostname from DNS, fall back to any label on IP entity
            if not hostname:
                hostname = ip_props.get("name", "") or ip_ent.get("name", "")

            row = {
                "network_cidr": network_cidr,
                "ip": address,
                "hostname": hostname or "",
                "fqdn": fqdn or "",
                "mac": mac or "",
                "state": state or "",
                "ip_version": "IPv4",
                "ptr_record": ptr or "",
                "bam_network_id": int(net_id),
                "bam_ip_entity_id": int(ip_ent["id"]),
                "source_system": SOURCE,
                "tenant": TENANT,
                "document": "",  # fill below
                "snapshot_at": snapshot_at,
                "_ingested_at": ingested_at,
                "_version": version,
            }
            row["document"] = build_document(row)

            # Append in column order expected by insert
            batch.append([
                row["network_cidr"], row["ip"], row["hostname"], row["fqdn"], row["mac"],
                row["state"], row["ip_version"], row["ptr_record"], row["bam_network_id"],
                row["bam_ip_entity_id"], row["source_system"], row["tenant"],
                row["document"], row["snapshot_at"], row["_ingested_at"], row["_version"]
            ])

        start += len(ip_addrs)

        # Flush in chunks to keep memory bounded
        if len(batch) >= 5000:
            ch_insert(batch)
            batch.clear()

    if batch:
        ch_insert(batch)

    print(f"Ingested {start} IP entries from {network_cidr} into {CH_DB}.{CH_TABLE} at {snapshot_at.isoformat()}.")

if __name__ == "__main__":
    run()
