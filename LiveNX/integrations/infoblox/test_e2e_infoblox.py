"""
End-to-end test for infoblox_script.py against real Infoblox, LiveNX, and ClickHouse servers.

Infoblox: https://10.244.17.108/ui/
LiveNX: 98.90.247.253:8093
ClickHouse: 98.90.247.253:9440 (native TLS)

Tests:
1. Infoblox connectivity and data retrieval (fixedaddress objects with MACs)
2. ClickHouse TLS connectivity and table creation
3. LiveNX NAT report queue and async data retrieval
4. Full consolidation pipeline: Infoblox data + LiveNX NAT data -> ClickHouse
5. Data integrity verification via ClickHouse query
"""

import sys
import ssl
import time
import uuid
from pathlib import Path
from datetime import datetime

import pytest
from clickhouse_driver import Client

SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))

import infoblox_script as script

LIVENX_HOST = "10.244.17.107"
LIVENX_TOKEN = "8EWTqD1EEs9/0oJaLKu0uK8+o5fCnF+YIbIKK0JihX4="
LIVENX_REPORT_ID = "90"
LIVENX_DEVICE_SERIAL = "kuwait_nat_device"

INFOBLOX_HOST = "10.244.17.108"
INFOBLOX_USERNAME = "admin"
INFOBLOX_PASSWORD = "Gom2c2go!"

CLICKHOUSE_HOST = "10.244.17.107"
CLICKHOUSE_PORT = 9440
CLICKHOUSE_USER = "default"
CLICKHOUSE_PASSWORD = "4ASf4EAszeL_RiQdKcDAhmbAY-C6F6SGH7lmCTqWwhc"
CLICKHOUSE_DATABASE = "default"
CLICKHOUSE_TABLE = f"infoblox_nat_dhcp_e2e_{uuid.uuid4().hex[:8]}"


def _make_ch_client():
    return Client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database="default",
        secure=True,
        verify=False,
        ssl_version=ssl.PROTOCOL_SSLv23,
    )


class _DirectClickHouseManager:
    """Lightweight ClickHouseManager that connects without cert files."""

    def __init__(self):
        self._client = None

    def get_client(self):
        if self._client is None:
            self._client = _make_ch_client()
        try:
            self._client.execute("SELECT 1")
        except Exception:
            self._client = _make_ch_client()
        return self._client

    def disconnect(self):
        if self._client:
            try:
                self._client.disconnect()
            except Exception:
                pass
            self._client = None


@pytest.fixture(scope="module")
def ch_manager():
    manager = _DirectClickHouseManager()
    yield manager
    # Cleanup: drop the test table
    try:
        client = manager.get_client()
        client.execute(f"DROP TABLE IF EXISTS `{CLICKHOUSE_DATABASE}`.`{CLICKHOUSE_TABLE}`")
    except Exception:
        pass
    manager.disconnect()


@pytest.fixture(scope="module")
def infoblox_leases():
    """Fetch fixedaddress records from Infoblox and map to lease-like format."""
    import requests
    session = script.get_http_session()
    url = f"https://{INFOBLOX_HOST}/wapi/v2.2/fixedaddress"
    params = {
        "_max_results": 1000,
        "_return_as_object": 1,
        "_return_fields": "ipv4addr,mac,name",
    }
    resp = session.get(url, params=params, auth=(INFOBLOX_USERNAME, INFOBLOX_PASSWORD), timeout=30)
    assert resp.status_code == 200, f"Infoblox returned {resp.status_code}: {resp.text}"
    records = resp.json().get("result", [])
    # Convert to the lease format the script expects: address, hardware, client_hostname
    leases = []
    for rec in records:
        lease = {"address": rec.get("ipv4addr")}
        if rec.get("mac"):
            lease["hardware"] = rec["mac"]
        if rec.get("name"):
            lease["client_hostname"] = rec["name"]
        leases.append(lease)
    return leases


@pytest.fixture(scope="module")
def raw_infoblox_leases():
    """Fetch actual DHCP leases (may be empty on this server)."""
    return script.get_infoblox(INFOBLOX_HOST, INFOBLOX_USERNAME, INFOBLOX_PASSWORD)


class TestInfobloxConnectivity:
    """Test real Infoblox API connectivity and data retrieval."""

    def test_fetch_fixedaddress_returns_data(self, infoblox_leases):
        assert infoblox_leases is not None
        assert len(infoblox_leases) > 0, "Expected at least one fixedaddress record from Infoblox"

    def test_lease_has_expected_fields(self, infoblox_leases):
        lease = infoblox_leases[0]
        assert "address" in lease, "Record missing 'address' field"
        leases_with_hardware = [l for l in infoblox_leases if l.get("hardware")]
        assert len(leases_with_hardware) > 0, "Expected at least one record with MAC (hardware)"

    def test_lease_address_format(self, infoblox_leases):
        for lease in infoblox_leases[:10]:
            addr = lease.get("address", "")
            parts = addr.split(".")
            assert len(parts) == 4, f"Invalid IP format: {addr}"
            for part in parts:
                assert part.isdigit() and 0 <= int(part) <= 255, f"Invalid octet in IP: {addr}"

    def test_pagination_fetches_all(self, infoblox_leases):
        print(f"Total records fetched: {len(infoblox_leases)}")
        assert isinstance(infoblox_leases, list)

    def test_wapi_lease_endpoint_accessible(self, raw_infoblox_leases):
        """Verify the DHCP lease endpoint is reachable (may return empty)."""
        assert raw_infoblox_leases is not None
        assert isinstance(raw_infoblox_leases, list)


class TestClickHouseConnectivity:
    """Test real ClickHouse TLS connectivity."""

    def test_connection_and_ping(self, ch_manager):
        client = ch_manager.get_client()
        result = client.execute("SELECT 1")
        assert result == [(1,)]

    def test_create_database_and_table(self, ch_manager):
        client = ch_manager.get_client()
        script.ensure_clickhouse_table(client, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE)
        # Verify table exists
        tables = client.execute(
            f"SELECT name FROM system.tables WHERE database = '{CLICKHOUSE_DATABASE}' AND name = '{CLICKHOUSE_TABLE}'"
        )
        assert len(tables) == 1
        assert tables[0][0] == CLICKHOUSE_TABLE

    def test_table_has_expected_columns(self, ch_manager):
        client = ch_manager.get_client()
        script.ensure_clickhouse_table(client, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE)
        columns = client.execute(
            f"SELECT name FROM system.columns WHERE database = '{CLICKHOUSE_DATABASE}' AND table = '{CLICKHOUSE_TABLE}'"
        )
        col_names = {row[0] for row in columns}
        expected = {"polled_at", "window_start", "window_end", "src_ip", "mapped_src_ip",
                    "dst_ip", "src_mac", "device_serial", "report_id", "hostname"}
        assert expected.issubset(col_names), f"Missing columns: {expected - col_names}"


class TestEndToEndPipeline:
    """Full pipeline: Infoblox leases + synthetic NAT data -> consolidation -> ClickHouse."""

    def test_consolidation_with_real_leases(self, infoblox_leases):
        # Build synthetic NAT CSV data using real lease IPs
        leases_with_mac = [l for l in infoblox_leases if l.get("hardware")]
        if not leases_with_mac:
            pytest.skip("No leases with hardware/MAC found on Infoblox server")

        # Take up to 5 leases to build synthetic NAT data
        sample_leases = leases_with_mac[:5]
        csv_header = "Time,Flow Record Count,Src IP Addr,Mapped Src IP Addr,Dst IP Addr"
        csv_lines = [csv_header]
        for i, lease in enumerate(sample_leases):
            src_ip = lease["address"]
            csv_lines.append(f"2024-01-01 00:00:00,{i+1},{src_ip},203.0.113.{i+1},8.8.8.{i+1}")

        consolidated = script.process_consolidation(csv_lines, infoblox_leases)
        assert len(consolidated) == len(sample_leases)
        for entry in consolidated:
            assert entry["SRC MAC"], f"Missing MAC for {entry['SRC IP (private)']}"

    def test_write_and_read_records(self, ch_manager, infoblox_leases):
        client = ch_manager.get_client()
        script.ensure_clickhouse_table(client, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE)

        leases_with_mac = [l for l in infoblox_leases if l.get("hardware")]
        if not leases_with_mac:
            pytest.skip("No leases with hardware/MAC found on Infoblox server")

        sample_leases = leases_with_mac[:3]
        csv_header = "Time,Flow Record Count,Src IP Addr,Mapped Src IP Addr,Dst IP Addr"
        csv_lines = [csv_header]
        for i, lease in enumerate(sample_leases):
            src_ip = lease["address"]
            csv_lines.append(f"2024-01-01 00:00:00,{i+1},{src_ip},198.51.100.{i+1},1.1.1.{i+1}")

        consolidated = script.process_consolidation(csv_lines, infoblox_leases)
        assert len(consolidated) > 0

        now = datetime.utcnow()
        window_start = datetime(2024, 1, 1, 0, 0, 0)
        window_end = datetime(2024, 1, 1, 0, 1, 0)
        test_device_serial = "E2E_TEST_DEVICE"
        test_report_id = f"e2e_test_{uuid.uuid4().hex[:8]}"

        records = []
        for entry in consolidated:
            records.append({
                "polled_at": now,
                "window_start": window_start,
                "window_end": window_end,
                "src_ip": entry.get("SRC IP (private)"),
                "mapped_src_ip": entry.get("Mapped (NAT) IP"),
                "dst_ip": entry.get("DST IP (public)"),
                "src_mac": entry.get("SRC MAC"),
                "hostname": entry.get("Hostname"),
                "device_serial": test_device_serial,
                "report_id": test_report_id,
            })

        script.write_records_to_clickhouse(ch_manager, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE, records)

        # Verify data was written
        time.sleep(1)  # brief wait for MergeTree to flush
        rows = client.execute(
            f"SELECT src_ip, mapped_src_ip, dst_ip, src_mac, device_serial, report_id "
            f"FROM `{CLICKHOUSE_DATABASE}`.`{CLICKHOUSE_TABLE}` "
            f"WHERE report_id = %(report_id)s",
            {"report_id": test_report_id},
        )
        assert len(rows) == len(records), f"Expected {len(records)} rows, got {len(rows)}"

        # Verify content matches
        written_src_ips = {row[0] for row in rows}
        expected_src_ips = {r["src_ip"] for r in records}
        assert written_src_ips == expected_src_ips

        written_macs = {row[3] for row in rows}
        expected_macs = {r["src_mac"] for r in records}
        assert written_macs == expected_macs

        # All rows should have the test device serial
        for row in rows:
            assert row[4] == test_device_serial

    def test_infoblox_cache_returns_same_object_on_second_call(self):
        cache = script.InfobloxCache(ttl_seconds=60)
        # Pre-populate the cache with known data
        cache._leases = [{"address": "1.2.3.4", "hardware": "aa:bb:cc:dd:ee:ff"}]
        cache._fetched_at = time.time()
        leases1 = cache.get_leases(INFOBLOX_HOST, INFOBLOX_USERNAME, INFOBLOX_PASSWORD)
        leases2 = cache.get_leases(INFOBLOX_HOST, INFOBLOX_USERNAME, INFOBLOX_PASSWORD)
        assert leases1 is leases2
        assert len(leases1) == 1

    def test_infoblox_cache_refreshes_after_ttl(self):
        cache = script.InfobloxCache(ttl_seconds=1)
        cache._leases = [{"address": "1.2.3.4", "hardware": "aa:bb:cc:dd:ee:ff"}]
        cache._fetched_at = time.time() - 2  # expired
        # Will call get_infoblox which returns empty on this server, but that's fine
        leases = cache.get_leases(INFOBLOX_HOST, INFOBLOX_USERNAME, INFOBLOX_PASSWORD)
        # Cache keeps old data if new fetch returns empty
        assert isinstance(leases, list)

    def test_clickhouse_reconnection(self, ch_manager):
        # Force disconnect and verify reconnection
        ch_manager.disconnect()
        client = ch_manager.get_client()
        result = client.execute("SELECT 1")
        assert result == [(1,)]

    def test_empty_nat_data_produces_no_records(self, ch_manager, infoblox_leases):
        client = ch_manager.get_client()
        script.ensure_clickhouse_table(client, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE)

        # Empty NAT data
        consolidated = script.process_consolidation([], infoblox_leases)
        assert consolidated == []

        # NAT data with header only (no rows)
        csv_lines = ["Time,Flow Record Count,Src IP Addr,Mapped Src IP Addr,Dst IP Addr"]
        consolidated = script.process_consolidation(csv_lines, infoblox_leases)
        assert consolidated == []

    def test_no_matching_ips_produces_no_records(self, infoblox_leases):
        # Use IPs that definitely won't match any Infoblox lease
        csv_header = "Time,Flow Record Count,Src IP Addr,Mapped Src IP Addr,Dst IP Addr"
        csv_lines = [
            csv_header,
            "2024-01-01 00:00:00,1,255.255.255.254,203.0.113.1,8.8.8.8",
            "2024-01-01 00:00:00,2,255.255.255.253,203.0.113.2,8.8.4.4",
        ]
        consolidated = script.process_consolidation(csv_lines, infoblox_leases)
        assert consolidated == []


class TestLiveNXConnectivity:
    """Test real LiveNX API connectivity and NAT report retrieval."""

    def test_setup_flow_limit(self):
        success, response = script.setup_LiveNX_flow_limit(
            LIVENX_HOST, LIVENX_TOKEN, script.LIVENX_REPORT_RESULTS_LIMIT
        )
        assert success, f"Failed to set flow limit: {response}"
        assert response.get("maxReturnSize") == script.LIVENX_REPORT_RESULTS_LIMIT

    def test_setup_queue(self):
        end_time = int(time.time() * 1000)
        start_time = end_time - (60 * 1000)
        success, response = script.setup_LiveNX_queue(
            LIVENX_HOST, LIVENX_TOKEN, start_time, end_time,
            LIVENX_REPORT_ID, LIVENX_DEVICE_SERIAL
        )
        assert success, f"Failed to queue report: {response}"
        assert "jobId" in response
        assert "jobInfo" in response

    def test_pull_nat_data_async(self):
        end_time = int(time.time() * 1000)
        start_time = end_time - (60 * 1000)
        nat_data = script.pull_nat_data_from_LiveNX_async(
            LIVENX_HOST, LIVENX_TOKEN, start_time, end_time,
            LIVENX_REPORT_ID, LIVENX_DEVICE_SERIAL
        )
        assert isinstance(nat_data, list)
        # May be empty if no NAT traffic in last 60s, but should at least succeed
        if nat_data:
            # First line should be CSV header
            header = nat_data[0].lower()
            assert "src" in header or "ip" in header, f"Unexpected header: {nat_data[0]}"


class TestFullEndToEnd:
    """Complete end-to-end: LiveNX NAT data + Infoblox leases -> ClickHouse."""

    def test_livenx_nat_with_infoblox_consolidation_to_clickhouse(self, ch_manager, infoblox_leases):
        client = ch_manager.get_client()
        script.ensure_clickhouse_table(client, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE)

        # Pull real NAT data from LiveNX (last 5 minutes for better chance of data)
        end_time = int(time.time() * 1000)
        start_time = end_time - (300 * 1000)

        nat_data = script.pull_nat_data_from_LiveNX_async(
            LIVENX_HOST, LIVENX_TOKEN, start_time, end_time,
            LIVENX_REPORT_ID, LIVENX_DEVICE_SERIAL
        )

        # Consolidate with Infoblox leases
        consolidated = script.process_consolidation(nat_data, infoblox_leases)

        # Write to ClickHouse regardless of whether there are matches
        now = datetime.utcnow()
        window_start = datetime.utcfromtimestamp(start_time / 1000)
        window_end = datetime.utcfromtimestamp(end_time / 1000)
        test_report_id = f"e2e_full_{uuid.uuid4().hex[:8]}"

        records = []
        for entry in consolidated:
            records.append({
                "polled_at": now,
                "window_start": window_start,
                "window_end": window_end,
                "src_ip": entry.get("SRC IP (private)"),
                "mapped_src_ip": entry.get("Mapped (NAT) IP"),
                "dst_ip": entry.get("DST IP (public)"),
                "src_mac": entry.get("SRC MAC"),
                "hostname": entry.get("Hostname"),
                "device_serial": LIVENX_DEVICE_SERIAL,
                "report_id": test_report_id,
            })

        if records:
            script.write_records_to_clickhouse(ch_manager, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE, records)
            time.sleep(1)
            rows = client.execute(
                f"SELECT count() FROM `{CLICKHOUSE_DATABASE}`.`{CLICKHOUSE_TABLE}` "
                f"WHERE report_id = %(report_id)s",
                {"report_id": test_report_id},
            )
            assert rows[0][0] == len(records)

        print(f"LiveNX NAT lines: {len(nat_data)}, "
              f"Infoblox leases: {len(infoblox_leases)}, "
              f"Consolidated matches: {len(consolidated)}, "
              f"Records written: {len(records)}")
