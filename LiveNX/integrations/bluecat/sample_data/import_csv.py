#!/usr/bin/env python3
"""
Script to import CSV data into ClickHouse ipam_devices table
Usage: python3 import_csv.py <csv_file>
"""

import sys
import csv
import os
from datetime import datetime
import clickhouse_connect
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ClickHouse configuration
CH_HOST = os.getenv("CH_HOST", "localhost")
CH_PORT = int(os.getenv("CH_PORT", "8123"))
CH_USER = os.getenv("CH_USER", "default")
CH_PASS = os.getenv("CH_PASS", "")
CH_DB = os.getenv("CH_DB", "netops")
CH_TABLE = os.getenv("CH_TABLE", "ipam_devices")
CH_SECURE = os.getenv("CH_SECURE", "false").lower() == "true"
CH_VERIFY_ENV = os.getenv("CH_VERIFY", "true").lower()
CH_VERIFY = (False if CH_VERIFY_ENV == "false" else (True if CH_VERIFY_ENV == "true" else CH_VERIFY_ENV))

def get_client():
    """Create ClickHouse client connection"""
    return clickhouse_connect.get_client(
        host=CH_HOST,
        port=CH_PORT,
        username=CH_USER,
        password=CH_PASS,
        database='default',
        secure=CH_SECURE,
        verify=CH_VERIFY
    )

def parse_datetime(dt_str):
    """Parse datetime string to datetime object"""
    if not dt_str or dt_str == '':
        return None
    try:
        # Handle ISO format with Z timezone
        if dt_str.endswith('Z'):
            dt_str = dt_str[:-1] + '+00:00'
        return datetime.fromisoformat(dt_str)
    except:
        return None

def import_csv(csv_file):
    """Import CSV data into ClickHouse"""

    # Read CSV file
    rows = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse datetime fields
            row['lease_start'] = parse_datetime(row.get('lease_start', ''))
            row['lease_end'] = parse_datetime(row.get('lease_end', ''))
            row['snapshot_at'] = parse_datetime(row.get('snapshot_at', ''))
            row['_ingested_at'] = parse_datetime(row.get('_ingested_at', ''))

            # Convert numeric fields
            row['bam_network_id'] = int(row.get('bam_network_id', 0))
            row['bam_ip_entity_id'] = int(row.get('bam_ip_entity_id', 0))
            row['_version'] = int(row.get('_version', 0))

            rows.append(row)

    if not rows:
        print("No data to import")
        return

    # Prepare data for insertion
    insert_data = []
    for row in rows:
        insert_data.append([
            row['network_cidr'],
            row['ip'],
            row['hostname'],
            row['fqdn'],
            row['mac'],
            row['state'],
            row['ip_version'],
            row['ptr_record'],
            row['bam_network_id'],
            row['bam_ip_entity_id'],
            row['lease_start'],
            row['lease_end'],
            row['lease_state'],
            row['source_system'],
            row['tenant'],
            row['document'],
            row['snapshot_at'],
            row['_ingested_at'],
            row['_version']
        ])

    # Connect to ClickHouse and insert data
    client = get_client()

    # Create database and table if not exists
    ddl = f"""
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

    for stmt in [s.strip() for s in ddl.split(";") if s.strip()]:
        client.command(stmt)

    # Insert data
    cols = [
        "network_cidr","ip","hostname","fqdn","mac","state","ip_version","ptr_record",
        "bam_network_id","bam_ip_entity_id","lease_start","lease_end","lease_state",
        "source_system","tenant","document","snapshot_at","_ingested_at","_version"
    ]

    client.insert(f"{CH_DB}.{CH_TABLE}", insert_data, column_names=cols)

    print(f"Successfully imported {len(rows)} rows into {CH_DB}.{CH_TABLE}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 import_csv.py <csv_file>")
        sys.exit(1)

    csv_file = sys.argv[1]
    if not os.path.exists(csv_file):
        print(f"Error: File {csv_file} not found")
        sys.exit(1)

    import_csv(csv_file)