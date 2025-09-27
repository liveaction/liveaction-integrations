import os
import time
import requests
from urllib.parse import urljoin
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ---------------------------
# CONFIG
# ---------------------------
BAM_BASE   = os.getenv("BAM_BASE", "https://bam.example.com")
USERNAME   = os.getenv("BAM_USER", "apiuser")
PASSWORD   = os.getenv("BAM_PASS", "apipassword")
VERIFY_TLS = os.getenv("BAM_VERIFY_TLS", "false").lower() == "true"
PAGE_SIZE  = int(os.getenv("PAGE_SIZE", "1000"))
INCLUDE_DHCP = os.getenv("INCLUDE_DHCP", "true").lower() == "true"  # Include DHCP lease info

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

def get_all_ipv4_blocks(auth_headers, parent_id=0, blocks=None):
    """Recursively fetch all IPv4 blocks and networks from BAM"""
    if blocks is None:
        blocks = []

    start = 0
    while True:
        # Get IPv4 blocks at this level
        ipv4_blocks = get_entities(auth_headers, parent_id, "IP4Block", start=start, count=PAGE_SIZE)
        if not ipv4_blocks:
            break

        for block in ipv4_blocks:
            blocks.append(block)
            # Recursively get child blocks
            get_all_ipv4_blocks(auth_headers, block["id"], blocks)

        start += len(ipv4_blocks)

    # Also get IPv4 networks at this level
    start = 0
    while True:
        ipv4_networks = get_entities(auth_headers, parent_id, "IP4Network", start=start, count=PAGE_SIZE)
        if not ipv4_networks:
            break

        blocks.extend(ipv4_networks)
        start += len(ipv4_networks)

    return blocks

def safe_get_absolute_name(entity):
    props = props_to_dict(entity.get("properties", ""))
    return props.get("absoluteName") or entity.get("name") or ""

def prefer(props, keys):
    """Return the first non-empty value from a list of keys in props dict"""
    for k in keys:
        if k in props and props[k]:
            return props[k]
    return None

def parse_epoch_maybe(v):
    """Parse epoch timestamp (ms or s) to datetime"""
    if v is None or v == "":
        return None
    try:
        x = int(v)
    except ValueError:
        return None
    # detect ms vs s
    if x > 10**12:
        x //= 1000
    elif x > 10**11:  # generous: treat as ms
        x //= 1000
    return datetime.fromtimestamp(x, tz=timezone.utc)

def list_dhcp_ranges(auth_headers, ip4net_id):
    """Fetch all DHCP ranges under a network"""
    ranges = []
    start = 0
    while True:
        chunk = get_entities(auth_headers, ip4net_id, "DHCP4Range", start=start, count=PAGE_SIZE)
        if not chunk:
            break
        ranges.extend(chunk)
        start += len(chunk)
    return ranges

def list_leases_in_range(auth_headers, dhcp_range_id):
    """Fetch all DHCP leases within a DHCP range"""
    leases = []
    start = 0
    while True:
        chunk = get_entities(auth_headers, dhcp_range_id, "DHCP4Lease", start=start, count=PAGE_SIZE)
        if not chunk:
            break
        leases.extend(chunk)
        start += len(chunk)
    return leases

def get_dhcp_lease_for_ip(auth_headers, ip_entity_id):
    """Try to find DHCP lease information for an IP address"""
    try:
        lease_links = get_linked_entities(auth_headers, ip_entity_id, "DHCP4Lease", start=0, count=1)
        if lease_links:
            lease_props = props_to_dict(lease_links[0].get("properties", ""))
            start_at = prefer(lease_props, ["startTime", "leaseStartTime", "validStart", "leaseStart"])
            end_at = prefer(lease_props, ["endTime", "leaseEndTime", "validEnd", "leaseExpiry", "expiryTime"])

            return {
                "lease_start": parse_epoch_maybe(start_at),
                "lease_end": parse_epoch_maybe(end_at),
                "lease_state": prefer(lease_props, ["state", "leaseState", "bindingState"]) or ""
            }
    except Exception:
        pass
    return {"lease_start": None, "lease_end": None, "lease_state": ""}

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
        database='default',
        secure=CH_SECURE,
        verify=CH_VERIFY,              # bool or path
        #client_cert=CH_CLIENT_CERT,    # optional
        #client_cert_key=CH_CLIENT_KEY       # optional
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
    lease_start      Nullable(DateTime64(3, 'UTC')),
    lease_end        Nullable(DateTime64(3, 'UTC')),
    lease_state      LowCardinality(String),
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
        "bam_network_id","bam_ip_entity_id","lease_start","lease_end","lease_state",
        "source_system","tenant","document","snapshot_at","_ingested_at","_version"
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

    # Add DHCP lease information if present
    if row.get('lease_start'):
        parts.append(f"Lease start: {row.get('lease_start').isoformat() if row.get('lease_start') else ''}")
    if row.get('lease_end'):
        parts.append(f"Lease end: {row.get('lease_end').isoformat() if row.get('lease_end') else ''}")
    if row.get('lease_state'):
        parts.append(f"Lease state: {row.get('lease_state')}")

    return " | ".join(parts).strip(" |")

def run():
    # Prepare ClickHouse (idempotent)
    ch_init()
    snapshot_at = datetime.now(timezone.utc)
    ingested_at = snapshot_at
    version = int(snapshot_at.timestamp() * 1000)  # ms since epoch

    auth = bam_login()

    # Fetch all IPv4 blocks and networks from BAM
    print("Discovering all IPv4 blocks and networks from BAM...")
    all_blocks = get_all_ipv4_blocks(auth)

    # Filter to only IP4Network entities (not IP4Block)
    networks = [block for block in all_blocks if block.get("type") == "IP4Network"]

    print(f"Found {len(networks)} IPv4 networks to process")

    SOURCE = "BlueCat BAM"
    TENANT = ""  # set if you segregate envs
    total_ip_count = 0

    # Process each network
    for network in networks:
        net_id = network["id"]
        net_props = props_to_dict(network.get("properties", ""))
        network_cidr = net_props.get("CIDR", network.get("name", ""))

        if not network_cidr:
            print(f"Warning: Network ID {net_id} has no CIDR, skipping...")
            continue

        print(f"Processing network: {network_cidr} (ID: {net_id})")

        start = 0
        batch = []
        network_ip_count = 0

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

                # Get DHCP lease information if enabled
                lease_info = {"lease_start": None, "lease_end": None, "lease_state": ""}
                if INCLUDE_DHCP:
                    lease_info = get_dhcp_lease_for_ip(auth, ip_ent["id"])

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
                    "lease_start": lease_info["lease_start"],
                    "lease_end": lease_info["lease_end"],
                    "lease_state": lease_info["lease_state"],
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
                    row["bam_ip_entity_id"], row["lease_start"], row["lease_end"], row["lease_state"],
                    row["source_system"], row["tenant"], row["document"], row["snapshot_at"],
                    row["_ingested_at"], row["_version"]
                ])

            start += len(ip_addrs)
            network_ip_count += len(ip_addrs)

            # Flush in chunks to keep memory bounded
            if len(batch) >= 5000:
                ch_insert(batch)
                batch.clear()

        if batch:
            ch_insert(batch)

        total_ip_count += network_ip_count
        print(f"  Ingested {network_ip_count} IP entries from {network_cidr}")

    # Also process standalone DHCP ranges if enabled
    if INCLUDE_DHCP:
        print("\nProcessing standalone DHCP ranges for additional lease information...")
        for network in networks:
            net_id = network["id"]
            net_props = props_to_dict(network.get("properties", ""))
            network_cidr = net_props.get("CIDR", network.get("name", ""))

            if not network_cidr:
                continue

            # Find DHCP ranges in this network
            dhcp_ranges = list_dhcp_ranges(auth, net_id)
            if dhcp_ranges:
                print(f"  Found {len(dhcp_ranges)} DHCP ranges in {network_cidr}")

                for dhcp_range in dhcp_ranges:
                    range_props = props_to_dict(dhcp_range.get("properties", ""))
                    range_name = dhcp_range.get("name", "")
                    start_ip = range_props.get("start", "")
                    end_ip = range_props.get("end", "")
                    print(f"    Processing DHCP range {range_name}: {start_ip} - {end_ip}")

    print(f"\nCompleted: Ingested {total_ip_count} total IP entries from {len(networks)} networks into {CH_DB}.{CH_TABLE} at {snapshot_at.isoformat()}.")

if __name__ == "__main__":
    run()