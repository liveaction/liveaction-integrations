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
LIVENX_POLL_INTERVAL_IN_SECONDS = 0  # 0 for no specific poll

MAX_LIVENX_RETRY_ATTEMPTS = 12
LIVENX_RETRY_BACKOFF_BASE = 5
LIVENX_REPORT_RESULTS_LIMIT = 100000

INFOBLOX_CACHE_TTL_SECONDS = 300
FAILED_WINDOW_MAX_RETRIES = 3

# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_http_session = None

def get_http_session():
    global _http_session
    if _http_session is None:
        _http_session = requests.Session()
        _http_session.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=requests.adapters.Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504]),
        )
        _http_session.mount("https://", adapter)
        _http_session.mount("http://", adapter)
    return _http_session


class InfobloxCache:
    def __init__(self, ttl_seconds=INFOBLOX_CACHE_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._leases = []
        self._fetched_at = 0

    def get_leases(self, infoblox_host, infoblox_username, infoblox_password):
        now = time.time()
        if self._leases and (now - self._fetched_at) < self._ttl:
            local_logger.info(f"Using cached Infoblox leases ({len(self._leases)} leases, age {now - self._fetched_at:.0f}s)")
            return self._leases
        leases = get_infoblox(infoblox_host, infoblox_username, infoblox_password)
        if leases:
            self._leases = leases
            self._fetched_at = now
        return self._leases


class ClickHouseManager:
    def __init__(self, host, port, user, password, database, ca_certs, certfile, keyfile):
        self._conn_params = {
            "host": host,
            "port": int(port),
            "user": user,
            "password": password,
            "database": database,
            "ca_certs": ca_certs,
            "certfile": certfile,
            "keyfile": keyfile,
        }
        self._client = None

    def _connect(self):
        self._client = connect_with_tls(**self._conn_params)
        if self._client is None:
            raise ConnectionError("Failed to establish ClickHouse connection.")
        return self._client

    def get_client(self):
        if self._client is None:
            self._connect()
        try:
            self._client.execute("SELECT 1")
        except Exception:
            local_logger.warning("ClickHouse connection stale, reconnecting...")
            try:
                self._client.disconnect()
            except Exception:
                pass
            self._client = None
            self._connect()
        return self._client

    def disconnect(self):
        if self._client:
            try:
                self._client.disconnect()
            except Exception:
                pass
            self._client = None


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
    session = get_http_session()

    # Step 1: Pull NAT data from LiveNX as CSV
    headers = {'Accept': '*/*', 'Authorization': f'Bearer {livenx_token}'}
    try:
        local_logger.info("Requesting NAT data from LiveNX...")
        livenx_response = session.get(livenx_nat_report_url, headers=headers, timeout=30)

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


def setup_LiveNX_flow_limit(livenx_host, livenx_token, report_results_limit):
    # To setup LiveNX Report Results Limit
    livenx_limit_url = f'https://{livenx_host}:8093/v1/reports/flow/limit'
    headers = {'Accept': '*/*', 'Authorization': f'Bearer {livenx_token}'}
    session = get_http_session()
    body =  {
                "maxReturnSize" : report_results_limit
            }
    try:
        livenx_response = session.put(livenx_limit_url, headers=headers, json=body, timeout=30)
        if livenx_response.status_code == 200:
            queue_response = livenx_response.json()
            limit = queue_response.get('maxReturnSize')
            local_logger.info(f"LiveNX report results limit = {limit} is setup successfully.")
            return True, queue_response
        else:
            local_logger.error(f"Unable to setup LiveNX report limit: {livenx_response.text}")
            return False, livenx_response.text
    except Exception as e:
        local_logger.error(f"Error on report limit from LiveNX: {e}")
        return False, str(e)


def setup_LiveNX_queue(livenx_host, livenx_token, start_time, end_time, report_id, device_serial):
    # To setup Top analysis report queue
    livenx_nat_report_url = f'https://{livenx_host}:8093/v1/reports/queue'
    local_logger.debug(f"Constructed URL: {livenx_nat_report_url}")

    # LiveNX doesn't accept same start and end time
    if start_time == end_time:
        start_time = end_time - 1

    headers = {'Accept': '*/*', 'Authorization': f'Bearer {livenx_token}'}
    session = get_http_session()
    body =  {
     "name": "Top Analysis for Infoblox",
     "reports":[
         {
                "reportId": {
                    "category": "flow",
                    "id": report_id
                },
                "parameters": {
                    "interface": "All Interfaces",
                    "displayFilter": "No Display Filtering",
                    "direction": "both",
                    "flowType": "basic",
                    "topAnalysisDisplayType": "raw",
                    "executionType": "aggregation",
                    "flexSearch": "",
                    "shouldWaitForDnsResolution": False,
                    "useFlowReportLimit": True,
                    "deviceSerial": device_serial,
                    "startTime": start_time,
                    "endTime": end_time
                },
                "reportName": "Report-1",
                "reportDescription": None
            }
        ]
    }
    try:
        livenx_response = session.post(livenx_nat_report_url, headers=headers, json=body, timeout=30)
        if livenx_response.status_code == 200:
            local_logger.debug("LiveNX Response Content (First 500 chars):")
            local_logger.debug(livenx_response.text[:500])  # Print a portion to check content format
            queue_response = livenx_response.json()
            return True, queue_response
        else:
            local_logger.error(f"Unable to setup LiveNX queue: {livenx_response.text}")
            return False, livenx_response.text
    except Exception as e:
        local_logger.error(f"Error pulling from LiveNX: {e}")
        return False, str(e)


def pull_nat_data_from_LiveNX_async(livenx_host, livenx_token, start_time, end_time, report_id, device_serial):

        livenx_nat_data = []
        session = get_http_session()

        local_logger.info(f"{start_time}-{end_time}: Requesting NAT data from LiveNX...")
        queue_status, queue_response = setup_LiveNX_queue(livenx_host, livenx_token, start_time, end_time, report_id, device_serial)

        if queue_status:
            job_id = queue_response.get('jobId')
            job_info = queue_response.get('jobInfo')
            local_logger.info(f"{start_time}-{end_time}: LiveNX queue job id: {job_id}")
            if job_info:
                headers = {'Accept': '*/*', 'Authorization': f'Bearer {livenx_token}'}

                result_url = job_info.get('result') + "/csv"

                result_response = None
                for i in range(MAX_LIVENX_RETRY_ATTEMPTS):
                    result_response = session.get(result_url, headers=headers, timeout=60)
                    if result_response.status_code == 400:
                        wait_time = LIVENX_RETRY_BACKOFF_BASE * (1.5 ** i)
                        local_logger.info(f"{start_time}-{end_time}: Retry attempt-{i+1}/{MAX_LIVENX_RETRY_ATTEMPTS}: Waiting {wait_time:.1f}s for LiveNX data")
                        time.sleep(wait_time)
                        continue
                    else:
                        break

                if result_response is None or result_response.status_code == 400:
                    local_logger.error(f"{start_time}-{end_time}: LiveNX report TIMED OUT after {MAX_LIVENX_RETRY_ATTEMPTS} retries (job {job_id}). DATA LOSS for this window.")
                    raise TimeoutError(f"LiveNX report job {job_id} not ready after {MAX_LIVENX_RETRY_ATTEMPTS} retries")

                if result_response.status_code == 200:

                    # Check if the response contains data (empty CSV check)
                    if not result_response.text.strip():
                        local_logger.info(f"{start_time}-{end_time}: LiveNX response contains no data.")
                        livenx_nat_data = []
                    else:
                        # Split the response text into lines and check the length of the data
                        raw_lines = result_response.text.splitlines()
                        # Some LiveNX responses prepend "Top Analysis" before the CSV header; drop it if present (can repeat)
                        while raw_lines and raw_lines[0].strip().lower() == "top analysis":
                            raw_lines = raw_lines[1:]
                        livenx_nat_data = raw_lines
                        local_logger.info(f"{start_time}-{end_time}: LiveNX Job {job_id} response: {len(livenx_nat_data)} lines.")
                        if len(livenx_nat_data) < 2:  # There should be at least a header line and one data line
                            local_logger.debug("LiveNX CSV has no data rows.")
                            livenx_nat_data = []
                        # Warn if result count hits the limit (possible truncation)
                        elif len(livenx_nat_data) - 1 >= LIVENX_REPORT_RESULTS_LIMIT:
                            local_logger.warning(
                                f"{start_time}-{end_time}: Result count ({len(livenx_nat_data)-1}) hit the "
                                f"{LIVENX_REPORT_RESULTS_LIMIT} limit — data may be TRUNCATED. "
                                f"Consider reducing poll interval to split into smaller windows."
                            )
                else:
                    local_logger.error(f"{start_time}-{end_time}: LiveNX returned status {result_response.status_code} for job {job_id}")
                    raise RuntimeError(f"LiveNX returned status {result_response.status_code} for job {job_id}")
        else:
            raise RuntimeError(f"Failed to queue LiveNX report for window {start_time}-{end_time}")

        return livenx_nat_data


# Step 2: Grab Infoblox DHCP leases
def get_infoblox(infoblox_host, infoblox_username, infoblox_password):

    # Infoblox API details
    wapi_version = '2.2'
    leases_url = f'https://{infoblox_host}/wapi/v{wapi_version}/lease'
    session = get_http_session()

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
            response = session.get(leases_url, params=params, auth=(infoblox_username, infoblox_password), timeout=30)

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


def process_consolidation(livenx_nat_data, infoblox_leases, trace_info=None):
    # Step 3: Match NAT IPs with DHCP leases and create a combined report
    consolidated_report = []
    local_logger.debug("Processing NAT and DHCP data for matching...")

    trace_src_ip = None
    trace_dst_ip = None
    if trace_info:
        trace_src_ip = trace_info.get('trace_src_ip')
        trace_dst_ip = trace_info.get('trace_dst_ip')


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

            if trace_info:
                match = False
                if trace_src_ip and trace_dst_ip:
                    if trace_src_ip == src_ip and trace_dst_ip == dst_ip:
                        match = True
                elif trace_src_ip:
                    if trace_src_ip == src_ip:
                        match = True
                elif trace_dst_ip:
                    if trace_dst_ip == dst_ip:
                        match = True
                if match:
                    local_logger.info(f"***** TRACE Entry: Src IP - {src_ip}, Mapped Src IP - {nat_ip}, Dst IP - {dst_ip} MAC - {mac_address}")


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


def write_records_to_clickhouse(ch_manager, database, table_name, records):
    if not records:
        local_logger.info("No records to insert into ClickHouse for this interval.")
        return

    client = ch_manager.get_client()
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


def generate_time_ranges(start, end, interval):
    """To generate intermediate time ranges with the given interval"""

    if interval == 0:
        return [(start, end)]

    ranges = []
    current = start

    while current + interval - 1 < end:
        next_value = current + interval -1
        ranges.append((current, next_value))
        current = next_value + 1

    # handle the final range if end is not reached exactly
    if current <= end:
        ranges.append((current, end))

    return ranges

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
    trace_src_ip = args.trace_src_ip
    trace_dst_ip = args.trace_dst_ip

    required_api_fields = {
        "livenx_host": livenx_host,
        "livenx_token": livenx_token,
        "device_serial": device_serial,
        "report_id": report_id,
    }
    missing_api = [key for key, value in required_api_fields.items() if not value]
    if missing_api:
        raise ValueError(f"Missing required LiveNX API configuration: {', '.join(missing_api)}")

    trace_info = {'trace_src_ip': trace_src_ip, 'trace_dst_ip': trace_dst_ip } if trace_src_ip or trace_dst_ip else None

    clickhouse_enabled = all([clickhouse_host, clickhouse_username, clickhouse_password])
    ch_manager = None
    if clickhouse_enabled:
        ch_manager = ClickHouseManager(
            host=clickhouse_host,
            port=int(clickhouse_port),
            user=clickhouse_username,
            password=clickhouse_password,
            database=clickhouse_database,
            ca_certs=clickhouse_cacerts,
            certfile=clickhouse_certfile,
            keyfile=clickhouse_keyfile,
        )

        client = ch_manager.get_client()
        ensure_clickhouse_table(client, clickhouse_database, clickhouse_table)
    else:
        local_logger.info("ClickHouse configuration not provided; results will be printed to stdout only.")

    poll_interval_seconds = max(1, int(args.poll_interval_seconds))
    run_once = getattr(args, 'once', False)
    infoblox_cache = InfobloxCache(ttl_seconds=INFOBLOX_CACHE_TTL_SECONDS)

    # Setup LiveNX Report Results Limit
    setup_LiveNX_flow_limit(livenx_host, livenx_token, LIVENX_REPORT_RESULTS_LIMIT)

    failed_windows = []

    try:

        loop_started = int(time.time() *1000)  # current timestamp
        start_time = loop_started - (INIT_DURATION_IN_SECONDS * 1000)
        end_time = loop_started

        while True:
            try:
                infoblox_leases = infoblox_cache.get_leases(infoblox_host, infoblox_username, infoblox_password)

                window_start_dt = datetime.utcfromtimestamp(start_time / 1000)
                window_end_dt = datetime.utcfromtimestamp(end_time / 1000)
                local_logger.info("\n" + ("-"*100) + f"\nStart: {window_start_dt.isoformat()} End: {window_end_dt.isoformat()}\n" + "-"*100)

                total_livenx_records = 0
                total_consolidated_records = 0
                interval = LIVENX_POLL_INTERVAL_IN_SECONDS * 1000
                time_ranges = generate_time_ranges(start_time, end_time, interval)

                # Also retry any previously failed windows
                retry_windows = []
                remaining_failed = []
                for fw in failed_windows:
                    if fw["retries"] < FAILED_WINDOW_MAX_RETRIES:
                        retry_windows.append(fw)
                    else:
                        local_logger.error(
                            f"PERMANENT DATA LOSS: Window {fw['start']}-{fw['end']} failed after "
                            f"{FAILED_WINDOW_MAX_RETRIES} retries. Discarding."
                        )
                failed_windows = remaining_failed

                if retry_windows:
                    local_logger.info(f"Retrying {len(retry_windows)} previously failed window(s)...")

                all_windows = [(tr[0], tr[1], None) for tr in time_ranges]
                all_windows += [(fw["start"], fw["end"], fw) for fw in retry_windows]

                for w_start, w_end, fw_entry in all_windows:
                    try:
                        livenx_nat_data = pull_nat_data_from_LiveNX_async(livenx_host, livenx_token, w_start, w_end, report_id, device_serial)
                        consolidated = process_consolidation(livenx_nat_data, infoblox_leases, trace_info)
                        polled_at = datetime.utcnow()

                        total_livenx_records += len(livenx_nat_data)
                        total_consolidated_records += len(consolidated)
                        records = []
                        for entry in consolidated:
                            records.append(
                                {
                                    "polled_at": polled_at,
                                    "window_start": datetime.utcfromtimestamp(w_start / 1000),
                                    "window_end": datetime.utcfromtimestamp(w_end / 1000),
                                    "src_ip": entry.get("SRC IP (private)"),
                                    "mapped_src_ip": entry.get("Mapped (NAT) IP"),
                                    "dst_ip": entry.get("DST IP (public)"),
                                    "src_mac": entry.get("SRC MAC"),
                                    "hostname": entry.get("Hostname"),
                                    "device_serial": device_serial,
                                    "report_id": report_id,
                                }
                            )

                        if ch_manager:
                            write_records_to_clickhouse(ch_manager, clickhouse_database, clickhouse_table, records)
                        else:
                            local_logger.debug(json.dumps(records[:MAX_ITEMS_TO_PRINT], default=str, indent=2))

                    except Exception as window_exc:
                        local_logger.error(f"Failed to process window {w_start}-{w_end}: {window_exc}")
                        retry_count = (fw_entry["retries"] + 1) if fw_entry else 1
                        failed_windows.append({"start": w_start, "end": w_end, "retries": retry_count})
                        local_logger.warning(f"Window {w_start}-{w_end} queued for retry (attempt {retry_count}/{FAILED_WINDOW_MAX_RETRIES})")

            except Exception as exc:
                local_logger.exception("Error during polling loop: %s", exc)

            elapsed = time.time() - end_time / 1000
            sleep_for = max(0, poll_interval_seconds - elapsed)

            local_logger.info("\n" + ("="*100) + f"\nTotal duration: {elapsed:.1f} seconds\n" +
                  f"LiveNX records: {total_livenx_records}, Infoblox leases: {len(infoblox_leases)}\n" +
                  f"Consolidated records: {total_consolidated_records}\n" +
                  f"Failed windows pending retry: {len(failed_windows)}\n" + "="*100)

            if run_once:
                local_logger.info("Single run complete (--once mode).")
                break

            if sleep_for > 0:
                local_logger.info(f"Sleeping for {sleep_for:.1f} seconds before next poll.")
                time.sleep(sleep_for)

            start_time = end_time + 1
            end_time = int(time.time() *1000)  # current timestamp


    except KeyboardInterrupt:
        local_logger.error("Polling stopped by user.")
    finally:
        if ch_manager:
            ch_manager.disconnect()

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
    parser.add_argument("--poll_interval_seconds", default=60, type=int, help="Polling interval in seconds.")
    parser.add_argument("--once", action="store_true", help="Run a single poll iteration and exit (non-continuous mode).")
    parser.add_argument("--trace_src_ip", help="Src IP to trace")
    parser.add_argument("--trace_dst_ip", help="Dst IP to trace")

    args = parser.parse_args()
    main(args)
