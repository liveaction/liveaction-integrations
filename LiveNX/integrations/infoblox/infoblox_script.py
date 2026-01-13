import requests
import csv
import urllib3
import time
import json
import argparse
import logging
import sys
import os
from datetime import datetime
import ssl
import re
from clickhouse_driver import Client

local_logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

INIT_DURATION_IN_SECONDS = 60  # use to fetch data first time based on the duration
MAX_ITEMS_TO_PRINT = 3

# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def connect_with_tls(host, port, user, password, database, ca_certs='/path/to/ca.pem', certfile='/etc/clickhouse-server/cacerts/ca.crt', keyfile='/etc/clickhouse-server/cacerts/ca.key'):
    if not(host and port and user and password and database):
        raise Exception("Missing Clickhouse Env setup")
    tls_params = {
        "secure": True,
        "verify": False,
        "ssl_version": ssl.PROTOCOL_SSLv23,
        "ca_certs": ca_certs,
        "certfile": certfile,
        "keyfile": keyfile,
    }

    try:
        client = Client(
            host=host,
            port=int(port),
            user=user,
            password=password,
            database=database,
            secure=tls_params["secure"],
            verify=tls_params["verify"],
            ssl_version=tls_params.get("ssl_version"),
            # ca_certs=tls_params.get("ca_certs"),
            certfile=tls_params.get("certfile"),
            keyfile=tls_params.get("keyfile"),
        )
        return client

    except Exception as e:
        local_logger.error(f"Error connecting to ClickHouse: {e}")
        return None


def pull_nat_data_from_LiveNX(livenx_host, livenx_token, start_time, end_time, report_id, device_serial):
    # Construct the LiveNX API URL
    livenx_nat_report_url = f'https://{livenx_host}:8093/v1/reports/flow/{report_id}/runAggregation.csv?startTime={start_time}&endTime={end_time}&topAnalysisDisplayType=raw&deviceSerial={device_serial}'
    local_logger.debug(f"Constructed URL: {livenx_nat_report_url}")

    livenx_nat_data = []

    # Step 1: Pull NAT data from LiveNX as CSV
    headers = {'Accept': '*/*', 'Authorization': f'Bearer {livenx_token}'}
    try:
        local_logger.info("Requesting NAT data from LiveNX...")
        livenx_response = requests.get(livenx_nat_report_url, headers=headers, verify=False, timeout=30)

        # Check the response status and print detailed logs
        local_logger.info(f"LiveNX Response Status: {livenx_response.status_code}")
        if livenx_response.status_code == 200:
            local_logger.info("LiveNX data fetched successfully.")
            local_logger.debug("LiveNX Response Content (First 500 chars):")
            local_logger.debug(livenx_response.text[:500])  # Print a portion to check content format

            # Check if the response contains data (empty CSV check)
            if not livenx_response.text.strip():
                local_logger.info("LiveNX response contains no data.")
                livenx_nat_data = []
            else:
                # Split the response text into lines and check the length of the data
                raw_lines = livenx_response.text.splitlines()
                # Some LiveNX responses prepend "Top Analysis" before the CSV header; drop it if present (can repeat)
                while raw_lines and raw_lines[0].strip().lower() == "top analysis":
                    raw_lines = raw_lines[1:]
                livenx_nat_data = raw_lines
                local_logger.debug(f"Parsed LiveNX data into {len(livenx_nat_data)} lines.")
                if len(livenx_nat_data) < 2:  # There should be at least a header line and one data line
                    local_logger.debug("LiveNX CSV has no data rows.")
                    livenx_nat_data = []
        else:
            local_logger.error(f"Error fetching LiveNX data: Status {livenx_response.status_code}, Content: {livenx_response.text}")
            livenx_nat_data = []
    except requests.exceptions.RequestException as e:
        local_logger.error(f"Error pulling from LiveNX: {e}")
        livenx_nat_data = []

    return livenx_nat_data

# Step 2: Grab Infoblox DHCP leases
def get_infoblox(infoblox_host, infoblox_username, infoblox_password):

    # Infoblox API details
    wapi_version = '2.2'
    leases_url = f'https://{infoblox_host}/wapi/v{wapi_version}/lease'
    
    page_id = None
    max_results = 1000

    infoblox_leases = []    
    try:
        while True:
            params = {
                "_paging": 1,
                "_return_as_object": 1,
                "_max_results": max_results,
                "_return_fields": "address,hardware,client_hostname"
            }

            if page_id:
                params["_page_id"] = page_id

            local_logger.debug("Requesting DHCP lease data from Infoblox...")
            response = requests.get(leases_url, params=params, auth=(infoblox_username, infoblox_password), verify=False, timeout=30)

            # Check the response status and print detailed logs
            local_logger.debug(f"Infoblox Response Status: {response.status_code}")
            if response.status_code == 200:
                data =  response.json()
                leases = data.get("result", [])
                infoblox_leases.extend(leases)
                local_logger.info(f"Infoblox returned {len(leases)} lease(s) in current attempt.")
                page_id = data.get("next_page_id")
                if not page_id:
                    break
                
            else:
                local_logger.error(f"Error fetching Infoblox data: Status {response.status_code}, Content: {response.text}")
                break            
            
    except requests.exceptions.RequestException as e:
        local_logger.error(f"Error pulling from Infoblox: {e}")        
    
    if infoblox_leases:
        local_logger.info(f"Total leases: {len(infoblox_leases)}")
        local_logger.debug(f"\nSample Infoblox Lease Data (First {MAX_ITEMS_TO_PRINT}):\n {infoblox_leases[:MAX_ITEMS_TO_PRINT]}")  # Print first 3 leases for debugging
    return infoblox_leases

def normalize_key(key):
    """Lowercase and replace non-alphanumerics with underscores for flexible header matching."""
    if not key:
        return ""
    return re.sub(r'[^a-z0-9]+', '_', str(key).strip().lower())

def pick(entry, candidates):
    """
    Return the first populated value for any of the provided candidate keys.
    Candidate keys should be normalized (see normalize_key).
    """
    normalized = {normalize_key(k): v for k, v in entry.items() if normalize_key(k)}
    for candidate in candidates:
        val = normalized.get(candidate)
        if val is not None and val != "":
            return val
    return None


def process_consolidation(livenx_nat_data, infoblox_leases):
    # Step 3: Match NAT IPs with DHCP leases and create a combined report
    consolidated_report = []
    local_logger.debug("Processing NAT and DHCP data for matching...")

    # Make a dictionary by address for quick retrieval
    lease_dict = {address: (hardware, lease.get('client_hostname')) 
                  for lease in infoblox_leases 
                  if (address := lease.get('address')) and (hardware := lease.get('hardware'))}

    if livenx_nat_data and lease_dict:
        csv_reader = csv.DictReader(livenx_nat_data)
        for i, nat_entry in enumerate(csv_reader):
            # Normalize column names to match LiveNX header variants
            src_ip = pick(nat_entry, ['src_ip_addr', 'src_ip'])
            dst_ip = pick(nat_entry, ['dst_ip_addr', 'dst_ip'])
            nat_ip = pick(
                nat_entry,
                [
                    'mapped_src_ip_addr',
                    'mapped_src_ip',
                    'mapped_ip_addr',
                    'mappest_ip_addr',  # observed variant/typo
                    'mapped_dst_ip_addr',
                ],
            )
            
            # Look for matching MAC address from DHCP leases
            mac_address, hostname = lease_dict.get(src_ip, (None, None))

            if i< MAX_ITEMS_TO_PRINT:
                # Debug NAT entry content (For First 3)
                local_logger.debug(f"Entry {i}: Src IP - {src_ip}, Mapped Src IP - {nat_ip}, Dst IP - {dst_ip} MAC - {mac_address}")

            if not mac_address:
                continue

            # Pack everything into a report
            report_entry = {
                'SRC IP (private)': src_ip,
                'Mapped (NAT) IP': nat_ip,
                'DST IP (public)': dst_ip,
                'SRC MAC': mac_address,
                'Hostname': hostname
            }
            consolidated_report.append(report_entry)

    # Step 4: Check if any data was processed
    if not consolidated_report:
        local_logger.info("No matching entries found between NAT and DHCP data.")
    else:
        local_logger.info(f"Found {len(consolidated_report)} matching entries.")

    return consolidated_report


def sanitize_identifier(identifier):
    """Basic protection to keep identifiers ClickHouse-safe."""
    return identifier.replace("`", "").replace(";", "")


def ensure_clickhouse_table(client, database, table_name):
    safe_db = sanitize_identifier(database)
    safe_table = sanitize_identifier(table_name)
    client.execute(f"CREATE DATABASE IF NOT EXISTS `{safe_db}`")
    create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS `{safe_db}`.`{safe_table}` (
            polled_at DateTime DEFAULT now(),
            window_start DateTime,
            window_end DateTime,
            src_ip String,
            mapped_src_ip String,
            dst_ip String,
            src_mac String,
            device_serial String,
            report_id String,
            hostname String
        ) ENGINE = MergeTree()
        ORDER BY (polled_at, src_ip)
    """
    client.execute(create_table_sql)

    # Ensure hostname column
    hostname_column_sql = f"ALTER TABLE `{safe_db}`.`{safe_table}` ADD COLUMN IF NOT EXISTS hostname String"
    client.execute(hostname_column_sql)


def write_records_to_clickhouse(client, database, table_name, records):
    if not records:
        local_logger.info("No records to insert into ClickHouse for this interval.")
        return

    safe_db = sanitize_identifier(database)
    safe_table = sanitize_identifier(table_name)
    insert_sql = f"""
        INSERT INTO `{safe_db}`.`{safe_table}`
            (polled_at, window_start, window_end, src_ip, mapped_src_ip, dst_ip, src_mac, hostname, device_serial, report_id)
        VALUES
    """
    payload = []
    for record in records:
        payload.append(
            (
                record.get("polled_at"),
                record.get("window_start"),
                record.get("window_end"),
                record.get("src_ip") or "",
                record.get("mapped_src_ip") or "",
                record.get("dst_ip") or "",
                record.get("src_mac") or "",
                record.get("hostname") or "",
                record.get("device_serial") or "",
                record.get("report_id") or "",
            )
        )
    client.execute(insert_sql, payload)
    local_logger.info(f"Wrote {len(payload)} record(s) to ClickHouse table `{safe_db}`.`{safe_table}`.")


def main(args):
    ## trace input arguments
    local_logger.debug(args)

    # Assign variables from arguments
    livenx_host = args.livenx_host
    livenx_token = args.livenx_token
    device_serial = args.device_serial
    report_id = args.report_id
    infoblox_host = args.infoblox_host
    infoblox_username = args.infoblox_username
    infoblox_password = args.infoblox_password
    clickhouse_host = args.clickhouse_host or os.getenv("CLICKHOUSE_HOST")
    clickhouse_username = args.clickhouse_username or os.getenv("CLICKHOUSE_USERNAME")
    clickhouse_password = args.clickhouse_password or os.getenv("CLICKHOUSE_PASSWORD")
    clickhouse_port = args.clickhouse_port or os.getenv("CLICKHOUSE_PORT", 9440)
    clickhouse_database = args.clickhouse_database or os.getenv("CLICKHOUSE_DATABASE", "inventory_db")
    clickhouse_table = args.clickhouse_table or os.getenv("CLICKHOUSE_TABLE", "infoblox_nat_dhcp")
    clickhouse_cacerts = args.clickhouse_cacerts or os.getenv("CLICKHOUSE_CACERTS", "/path/to/ca.pem")
    clickhouse_certfile = args.clickhouse_certfile or os.getenv("CLICKHOUSE_CERTFILE", "/etc/clickhouse-server/cacerts/ca.crt")
    clickhouse_keyfile = args.clickhouse_keyfile or os.getenv("CLICKHOUSE_KEYFILE", "/etc/clickhouse-server/cacerts/ca.key")

    required_api_fields = {
        "livenx_host": livenx_host,
        "livenx_token": livenx_token,
        "device_serial": device_serial,
        "report_id": report_id,
    }
    missing_api = [key for key, value in required_api_fields.items() if not value]
    if missing_api:
        raise ValueError(f"Missing required LiveNX API configuration: {', '.join(missing_api)}")

    clickhouse_enabled = all([clickhouse_host, clickhouse_username, clickhouse_password])
    client = None
    if clickhouse_enabled:
        client = connect_with_tls(
            host=clickhouse_host,
            port=int(clickhouse_port),
            user=clickhouse_username,
            password=clickhouse_password,
            database=clickhouse_database,
            ca_certs=clickhouse_cacerts,
            certfile=clickhouse_certfile,
            keyfile=clickhouse_keyfile,
        )

        if client is None:
            raise ConnectionError("Failed to establish ClickHouse connection.")

        ensure_clickhouse_table(client, clickhouse_database, clickhouse_table)
    else:
        local_logger.info("ClickHouse configuration not provided; results will be printed to stdout only.")

    poll_interval_seconds = max(1, int(args.poll_interval_seconds))

    try:

        loop_started = int(time.time() *1000)  # current timestamp
        start_time = loop_started - (INIT_DURATION_IN_SECONDS * 1000) 
        end_time = loop_started

        while True:            
            try:

                livenx_nat_data = pull_nat_data_from_LiveNX(livenx_host, livenx_token, start_time, end_time, report_id, device_serial)
                infoblox_leases = get_infoblox(infoblox_host, infoblox_username, infoblox_password)
                consolidated = process_consolidation(livenx_nat_data, infoblox_leases)

                window_start_dt = datetime.utcfromtimestamp(start_time / 1000)
                window_end_dt = datetime.utcfromtimestamp(end_time / 1000)
                polled_at = datetime.utcnow()

                local_logger.info("\n" + ("-"*100) + f"\nStart: {window_start_dt.isoformat()} End: {window_end_dt.isoformat()}\n" + "-"*100)

                records = []
                for entry in consolidated:
                    records.append(
                        {
                            "polled_at": polled_at,
                            "window_start": window_start_dt,
                            "window_end": window_end_dt,
                            "src_ip": entry.get("SRC IP (private)"),
                            "mapped_src_ip": entry.get("Mapped (NAT) IP"),
                            "dst_ip": entry.get("DST IP (public)"),
                            "src_mac": entry.get("SRC MAC"),
                            "hostname": entry.get("Hostname"),
                            "device_serial": device_serial,
                            "report_id": report_id,
                        }
                    )

                if client:
                    write_records_to_clickhouse(client, clickhouse_database, clickhouse_table, records)
                else:
                    local_logger.debug(json.dumps(records[:MAX_ITEMS_TO_PRINT], default=str, indent=2)) # print first 3 records
            except Exception as exc:
                local_logger.exception("Error during polling loop: %s", exc)

            elapsed = time.time() - end_time / 1000
            sleep_for = max(0, poll_interval_seconds - elapsed)

            local_logger.info("\n" + ("="*100) + f"\nTotal duration: {elapsed:.1f} seconds\n" + 
                  f"LiveNX records: {len(livenx_nat_data)}, Infoblox leases: {len(infoblox_leases)}\n" +
                  f"Consolidated records: {len(consolidated)}\n" + "="*100)

            if sleep_for > 0:
                local_logger.info(f"Sleeping for {sleep_for:.1f} seconds before next poll.")
                time.sleep(sleep_for)

            start_time = end_time + 1
            end_time = int(time.time() *1000)  # current timestamp


    except KeyboardInterrupt:
        local_logger.error("Polling stopped by user.")
    finally:
        if client:
            client.disconnect()

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Script to fetch NAT data from LiveNX and DHCP leases from Infoblox, then consolidate into a report.")
    parser.add_argument("--livenx_host", required=True, help="LiveNX host IP address")
    parser.add_argument("--livenx_token", required=True, help="LiveNX API token")
    parser.add_argument("--report_id", required=True, help="Report Id for LiveNX")
    parser.add_argument("--device_serial", required=True, help="Device serial number for LiveNX")
    parser.add_argument("--infoblox_host", required=True, help="Infoblox host address")
    parser.add_argument("--infoblox_username", required=True, help="Infoblox username")
    parser.add_argument("--infoblox_password", required=True, help="Infoblox password")
    parser.add_argument("--clickhouse_host", help="ClickHouse host (or set CLICKHOUSE_HOST)")
    parser.add_argument("--clickhouse_port", type=int, help="ClickHouse port (or set CLICKHOUSE_PORT)")
    parser.add_argument("--clickhouse_username", help="ClickHouse username (or set CLICKHOUSE_USERNAME)")
    parser.add_argument("--clickhouse_password", help="ClickHouse password (or set CLICKHOUSE_PASSWORD)")
    parser.add_argument("--clickhouse_database", help="ClickHouse database name (or set CLICKHOUSE_DATABASE; default inventory_db)")
    parser.add_argument("--clickhouse_table", help="ClickHouse table name (or set CLICKHOUSE_TABLE; default infoblox_nat_dhcp)")
    parser.add_argument("--clickhouse_cacerts", help="Path to ClickHouse CA certs (or set CLICKHOUSE_CACERTS)")
    parser.add_argument("--clickhouse_certfile", help="Path to ClickHouse client cert (or set CLICKHOUSE_CERTFILE)")
    parser.add_argument("--clickhouse_keyfile", help="Path to ClickHouse client key (or set CLICKHOUSE_KEYFILE)")
    parser.add_argument("--poll_interval_seconds", default=60, type=int, help="Polling interval in seconds. Default: 60")

    args = parser.parse_args()
    main(args)
