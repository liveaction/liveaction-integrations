#!/usr/bin/env python3
"""
ClickHouse Aggregation Script
Performs aggregation queries from basic_raw to basic_entity_app_site_1m table
"""

import argparse
import base64
import csv
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, List, Optional, Tuple


# Aggregation level configurations
AGGREGATION_LEVELS = {
    '1m': {
        'source': 'livenx_flowdb.basic_raw',
        'dest': 'livenx_flowdb.basic_entity_app_site_1m',
        'time_function': 'toStartOfMinute',
        'interval_minutes': 1,
        'description': 'Raw to 1-minute aggregation'
    },
    '5m': {
        'source': 'livenx_flowdb.basic_entity_app_site_1m',
        'dest': 'livenx_flowdb.basic_entity_app_site_5m',
        'time_function': 'toStartOfFiveMinutes',
        'interval_minutes': 5,
        'description': '1-minute to 5-minute aggregation'
    },
    '60m': {
        'source': 'livenx_flowdb.basic_entity_app_site_5m',
        'dest': 'livenx_flowdb.basic_entity_app_site_60m',
        'time_function': 'toStartOfHour',
        'interval_minutes': 60,
        'description': '5-minute to 60-minute aggregation'
    },
    '360m': {
        'source': 'livenx_flowdb.basic_entity_app_site_60m',
        'dest': 'livenx_flowdb.basic_entity_app_site_360m',
        'time_function': 'toStartOfInterval(time, INTERVAL 6 HOUR)',
        'interval_minutes': 360,
        'description': '60-minute to 360-minute (6-hour) aggregation'
    }
}


def parse_site_mapping_csv(filepath: str) -> List[Dict]:
    """
    Parse LiveAction_sites.csv file containing site name to IP range mappings
    
    Expected CSV format:
    Site Name,Site IP Ranges
    "New York","10.1.0.0/16,192.168.1.0/24"
    "London","10.2.0.0/16"
    
    Returns:
        List of dicts with 'name' and 'networks' (list of ipaddress.IPv4Network objects)
    """
    site_mappings = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Handle different possible column names
            site_col = None
            ip_col = None
            
            for col in reader.fieldnames:
                if 'site' in col.lower() and 'name' in col.lower():
                    site_col = col
                elif 'ip' in col.lower() and 'range' in col.lower():
                    ip_col = col
            
            if not site_col or not ip_col:
                # Try exact matches
                if 'Site Name' in reader.fieldnames:
                    site_col = 'Site Name'
                if 'Site IP Ranges' in reader.fieldnames:
                    ip_col = 'Site IP Ranges'
            
            if not site_col or not ip_col:
                raise ValueError(f"Could not find required columns. Found: {reader.fieldnames}")
            
            for row in reader:
                site_name = row[site_col].strip()
                ip_ranges = row[ip_col].strip()
                
                if not site_name or not ip_ranges:
                    continue
                
                # Parse IP ranges (comma-separated)
                networks = []
                for ip_range in ip_ranges.split(','):
                    ip_range = ip_range.strip().strip('"')
                    try:
                        network = ipaddress.IPv4Network(ip_range, strict=False)
                        networks.append(network)
                    except (ipaddress.AddressValueError, ValueError) as e:
                        print(f"\033[93mWarning: Invalid IP range '{ip_range}' for site '{site_name}': {e}\033[0m")
                        continue
                
                if networks:
                    site_mappings.append({
                        'name': site_name,
                        'networks': networks
                    })
        
        print(f"Loaded {len(site_mappings)} site mappings from {filepath}")
        return site_mappings
        
    except FileNotFoundError:
        raise ValueError(f"Site mapping file not found: {filepath}")
    except Exception as e:
        raise ValueError(f"Error parsing site mapping file: {e}")


def generate_site_mapping_case_statement(site_mappings: List[Dict], ip_field: str, original_field: str) -> str:
    """
    Generate ClickHouse CASE statement for IP to site name mapping.
    Longer prefix lengths (more specific networks) take priority over shorter ones.
    
    Args:
        site_mappings: List of site mappings from parse_site_mapping_csv
        ip_field: The IP field to check (e.g., 'DestIpv4', 'SourceIpv4')
        original_field: The original site name field to fall back to
    
    Returns:
        CASE WHEN statement as string
    """
    if not site_mappings:
        return original_field
    
    # Collect all networks with their site names and prefix lengths
    all_networks = []
    for site in site_mappings:
        for network in site['networks']:
            all_networks.append({
                'network': network,
                'site_name': site['name'],
                'prefix_length': network.prefixlen
            })
    
    # Sort by prefix length in descending order (longer/more specific first)
    # This ensures /24 networks are checked before /16 networks, etc.
    all_networks.sort(key=lambda x: x['prefix_length'], reverse=True)
    
    case_parts = ["CASE"]
    
    # Generate conditions in order of specificity
    for net_info in all_networks:
        network = net_info['network']
        site_name = net_info['site_name']
        
        # Convert network to ClickHouse IP range check
        network_int = int(network.network_address)
        broadcast_int = int(network.broadcast_address)
        
        # ClickHouse condition for checking if IP is in range
        condition = (
            f"(toIPv4OrDefault({ip_field}) >= toIPv4({network_int}) AND "
            f"toIPv4OrDefault({ip_field}) <= toIPv4({broadcast_int}))"
        )
        
        case_parts.append(f"  WHEN {condition} THEN '{site_name}'")
    
    # Fall back to original field if no match
    case_parts.append(f"  ELSE {original_field}")
    case_parts.append("END")
    
    return "\n".join(case_parts)


class ClickHouseAggregator:
    """Main class for running ClickHouse aggregation queries"""
    
    def __init__(self, host: str = 'localhost', port: int = 8123,
                 user: str = 'default', password: str = '',
                 database: str = 'default', timeout: int = 300,
                 use_https: bool = False, verify_ssl: bool = True, verify_hostname = False,
                 ca_cert: Optional[str] = None, client_cert: Optional[str] = None,
                 client_key: Optional[str] = None, parallel_workers: int = 1,
                 site_mapping_file: Optional[str] = None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.timeout = timeout
        self.use_https = use_https
        self.verify_ssl = verify_ssl
        self.verify_hostname = verify_hostname
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.parallel_workers = parallel_workers
        
        # Load site mappings if provided
        self.site_mappings = []
        if site_mapping_file:
            try:
                self.site_mappings = parse_site_mapping_csv(site_mapping_file)
            except ValueError as e:
                print(f"\033[93mWarning: {e}\033[0m")
                print("Continuing without site IP mappings...")
        
        # Build URL and SSL context
        self.base_url = self._build_url(host, port, use_https)
        self.ssl_context = self._create_ssl_context(verify_ssl, verify_hostname, ca_cert, client_cert, client_key)
        
        # Thread safety for progress tracking
        self.progress_lock = Lock()
        self.completed_batches = 0
        self.failed_batches = 0
    
    def _build_url(self, host: str, port: int, use_https: bool = False) -> str:
        """Build the ClickHouse HTTP interface URL"""
        protocol = "https" if use_https else "http"
        return f"{protocol}://{host}:{port}/"
    
    def _create_ssl_context(self, verify_ssl: bool = True, verify_hostname: bool = False, ca_cert: Optional[str] = None,
                          client_cert: Optional[str] = None, client_key: Optional[str] = None) -> Optional[ssl.SSLContext]:
        """Create SSL context for HTTPS connections"""
        if not self.use_https:
            return None
            
        # Create context
        if not verify_ssl and not ca_cert and not client_cert:
            try:
                return ssl._create_unverified_context()
            except:
                pass
        
        ctx = ssl.create_default_context()
        
        if not verify_hostname:
            ctx.check_hostname = False
        
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        # Set CA certificate if provided
        if ca_cert:
            if os.path.isfile(ca_cert):
                ctx.load_verify_locations(ca_cert)
            else:
                raise ValueError(f"CA certificate file not found: {ca_cert}")
        
        # Set client certificate and key for mutual TLS
        if client_cert or client_key:
            if not (client_cert and client_key):
                raise ValueError("Both client certificate and key must be provided for mutual TLS")
            if not os.path.isfile(client_cert):
                raise ValueError(f"Client certificate file not found: {client_cert}")
            if not os.path.isfile(client_key):
                raise ValueError(f"Client key file not found: {client_key}")
            ctx.load_cert_chain(client_cert, client_key)
        
        return ctx
    
    def execute_query(self, query: str, format: str = 'TabSeparated') -> Tuple[str, Dict[str, str]]:
        """
        Execute a query and return the result with response headers
        
        Returns:
            Tuple of (response_body, headers_dict)
        """
        headers = {
            'X-ClickHouse-Database': self.database,
            'X-ClickHouse-Format': format,
        }
        
        # Add Basic Authentication header
        if self.user or self.password:
            credentials = f"{self.user}:{self.password}".encode('utf-8')
            b64_credentials = base64.b64encode(credentials).decode('ascii')
            headers['Authorization'] = f'Basic {b64_credentials}'
        
        req = urllib.request.Request(
            self.base_url,
            data=query.encode('utf-8'),
            headers=headers
        )
        
        try:
            # Use SSL context if HTTPS
            if self.use_https and self.ssl_context:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                    result = response.read().decode('utf-8')
                    headers_dict = dict(response.headers)
                    return result, headers_dict
            else:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    result = response.read().decode('utf-8')
                    headers_dict = dict(response.headers)
                    return result, headers_dict
        except urllib.error.HTTPError as e:
            error_msg = e.read().decode('utf-8')
            raise Exception(f"Query failed (HTTP {e.code}): {error_msg}")
        except urllib.error.URLError as e:
            raise Exception(f"Connection failed: {e}")
        except ssl.SSLError as e:
            raise Exception(f"SSL error: {e}")
    
    def test_connection(self) -> bool:
        """Test the connection to ClickHouse instance"""
        try:
            self.execute_query("SELECT 1")
            return True
        except Exception as e:
            print(f"\033[91mConnection test failed: {e}\033[0m")
            return False
    
    def get_table_count(self, table: str) -> int:
        """Get row count for a table"""
        try:
            result, _ = self.execute_query(f"SELECT count() FROM {table}")
            return int(result.strip())
        except Exception as e:
            print(f"\033[91mFailed to get count for {table}: {e}\033[0m")
            return -1
    
    def get_date_range(self, table: str) -> Tuple[Optional[str], Optional[str]]:
        """Get min and max dates from a table"""
        try:
            query = f"""
            SELECT 
                min(time) as min_time,
                max(time) as max_time
            FROM {table}
            """
            result, _ = self.execute_query(query)
            if result.strip():
                parts = result.strip().split('\t')
                if len(parts) == 2:
                    return parts[0], parts[1]
            return None, None
        except Exception as e:
            print(f"\033[91mFailed to get date range for {table}: {e}\033[0m")
            return None, None
    
    def create_aggregation_query(self, start_time: str, end_time: str, 
                                source_table: str = 'livenx_flowdb.basic_raw',
                                dest_table: str = 'livenx_flowdb.basic_entity_app_site_1m',
                                time_function: str = 'toStartOfMinute',
                                level: Optional[str] = None) -> str:
        """
        Create the aggregation query for different aggregation levels
        
        Args:
            start_time: Start time in format 'YYYY-MM-DD HH:MM:SS'
            end_time: End time in format 'YYYY-MM-DD HH:MM:SS'
            source_table: Source table name
            dest_table: Destination table name
            time_function: ClickHouse time function for aggregation
            level: Aggregation level (1m, 5m, 60m, 360m)
        
        Returns:
            The INSERT SELECT query
        """
        # Determine if source is raw table (has additional fields)
        is_raw_source = 'basic_raw' in source_table
        
        # Build time expression
        if '(' in time_function and ')' in time_function:
            # Complex function like toStartOfInterval
            time_expr = time_function
        else:
            # Simple function like toStartOfMinute
            time_expr = f"{time_function}(time)"
        
        # Determine site name fields based on IP mappings
        if is_raw_source and self.site_mappings:
            # Use IP-based mapping for raw table that has DestIpv4 and SourceIpv4 columns
            dest_site_expr = generate_site_mapping_case_statement(
                self.site_mappings, 'DestIpv4', 'DestSiteName'
            )
            source_site_expr = generate_site_mapping_case_statement(
                self.site_mappings, 'SourceIpv4', 'SourceSiteName'
            )
        else:
            # Use original fields for non-raw tables or when no mappings provided
            dest_site_expr = 'DestSiteName'
            source_site_expr = 'SourceSiteName'
        
        query = f"""
        INSERT INTO {dest_table}
        SELECT
            {time_expr} as StartTime,
            FlowDirection,
            DeviceSiteRegion,
            DeviceSiteName,
            DeviceSerial,
            EgressIfWanType,
            EgressSpName,
            DeviceAndEgressIfTagSetId,
            EgressIfIndex,
            EgressIfName,
            IngressIfWanType,
            IngressSpName,
            DeviceAndIngressIfTagSetId,
            IngressIfIndex,
            IngressIfName,
            Dscp,
            ApplicationGroupName,
            ApplicationName,
            DestCountryName,
            {dest_site_expr} as DestSiteName,
            SourceCountryName,
            {source_site_expr} as SourceSiteName,
            sum(SumFlowCount) as SumFlowCount,
            sum(SumPackets) as SumPackets,
            sum(SumOctets) as SumOctets,
            max(Sampled) as Sampled
        FROM {source_table}
        WHERE time >= '{start_time}'
          AND time < '{end_time}'
        GROUP BY
            StartTime,
            FlowDirection,
            DeviceSiteRegion,
            DeviceSiteName,
            DeviceSerial,
            EgressIfWanType,
            EgressSpName,
            DeviceAndEgressIfTagSetId,
            EgressIfIndex,
            EgressIfName,
            IngressIfWanType,
            IngressSpName,
            DeviceAndIngressIfTagSetId,
            IngressIfIndex,
            IngressIfName,
            Dscp,
            ApplicationGroupName,
            ApplicationName,
            DestCountryName,
            DestSiteName,
            SourceCountryName,
            SourceSiteName
        """
        return query
    
    def _execute_batch(self, batch_num: int, total_batches: int, batch_start: str, batch_end: str,
                       source_table: str, dest_table: str, time_function: str, level: Optional[str]) -> Tuple[bool, Dict]:
        """Execute a single batch aggregation (used for parallel processing)"""
        query = self.create_aggregation_query(batch_start, batch_end, source_table, dest_table, time_function, level)
        
        start = time.perf_counter()
        try:
            result, headers = self.execute_query(query)
            elapsed = time.perf_counter() - start
            
            # Parse ClickHouse summary
            summary_header = headers.get('X-ClickHouse-Summary', '{}')
            try:
                summary = json.loads(summary_header)
                rows_read = summary.get('read_rows', 0)
                result_rows = summary.get('result_rows', 0)
                bytes_read = summary.get('read_bytes', 0)
                
                with self.progress_lock:
                    self.completed_batches += 1
                    print(f"  Batch {batch_num}/{total_batches} [{batch_start} to {batch_end}]: "
                          f"\033[92mCompleted in {elapsed:.2f}s - Read: {rows_read:,} rows, Inserted: {result_rows:,} rows\033[0m")
                
                return True, {
                    'batch_num': batch_num,
                    'elapsed': elapsed,
                    'rows_read': rows_read,
                    'result_rows': result_rows,
                    'bytes_read': bytes_read
                }
            except:
                with self.progress_lock:
                    self.completed_batches += 1
                    print(f"  Batch {batch_num}/{total_batches}: \033[92mCompleted in {elapsed:.2f}s\033[0m")
                return True, {'batch_num': batch_num, 'elapsed': elapsed}
        
        except Exception as e:
            with self.progress_lock:
                self.failed_batches += 1
                print(f"  Batch {batch_num}/{total_batches} [{batch_start} to {batch_end}]: \033[91mFailed: {e}\033[0m")
            return False, {'batch_num': batch_num, 'error': str(e)}
    
    def run_aggregation(self, start_time: str, end_time: str,
                       source_table: str = 'livenx_flowdb.basic_raw',
                       dest_table: str = 'livenx_flowdb.basic_entity_app_site_1m',
                       batch_size: int = 0,
                       dry_run: bool = False,
                       time_function: str = 'toStartOfMinute',
                       level: Optional[str] = None) -> bool:
        """
        Run the aggregation query, optionally in batches
        
        Args:
            start_time: Start time in format 'YYYY-MM-DD HH:MM:SS'
            end_time: End time in format 'YYYY-MM-DD HH:MM:SS'
            source_table: Source table name
            dest_table: Destination table name
            batch_size: Number of aggregation intervals per batch (0 for no batching)
            dry_run: If True, only show the query without executing
            time_function: ClickHouse time function for aggregation
            level: Aggregation level
        
        Returns:
            True if successful, False otherwise
        """
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
        
        # Determine aggregation interval in minutes
        if level and level in AGGREGATION_LEVELS:
            interval_minutes = AGGREGATION_LEVELS[level]['interval_minutes']
        else:
            # Default to 1 minute for custom tables
            interval_minutes = 1
        
        if batch_size <= 0:
            # Single query for entire range
            query = self.create_aggregation_query(start_time, end_time, source_table, dest_table, time_function, level)
            
            if dry_run:
                print("\033[94mDry run - Query to execute:\033[0m")
                print(query)
                return True
            
            print(f"Aggregating data from {start_time} to {end_time}...")
            start = time.perf_counter()
            
            try:
                result, headers = self.execute_query(query)
                elapsed = time.perf_counter() - start
                
                # Parse ClickHouse summary from headers
                summary_header = headers.get('X-ClickHouse-Summary', '{}')
                try:
                    summary = json.loads(summary_header)
                    rows_read = summary.get('read_rows', 0)
                    bytes_read = summary.get('read_bytes', 0)
                    result_rows = summary.get('result_rows', 0)
                    
                    print(f"\033[92mCompleted in {elapsed:.2f} seconds\033[0m")
                    print(f"  Rows read: {rows_read:,}")
                    print(f"  Bytes read: {bytes_read:,} ({bytes_read/(1024*1024):.2f} MB)")
                    print(f"  Rows inserted: {result_rows:,}")
                except:
                    print(f"\033[92mCompleted in {elapsed:.2f} seconds\033[0m")
                
                return True
                
            except Exception as e:
                print(f"\033[91mAggregation failed: {e}\033[0m")
                return False
        
        else:
            # Batch processing - batch by multiples of aggregation granularity
            batch_minutes = batch_size * interval_minutes
            batch_delta = timedelta(minutes=batch_minutes)
            total_time_minutes = (end_dt - start_dt).total_seconds() / 60
            total_batches = int(total_time_minutes / batch_minutes)
            if total_time_minutes % batch_minutes > 0:
                total_batches += 1

            
            # Generate all batch time ranges
            batches = []
            current_dt = start_dt
            batch_num = 1
            
            while current_dt < end_dt:
                batch_end_dt = min(current_dt + batch_delta, end_dt)
                batch_start = current_dt.strftime('%Y-%m-%d %H:%M:%S')
                batch_end = batch_end_dt.strftime('%Y-%m-%d %H:%M:%S')
                batches.append((batch_num, batch_start, batch_end))
                current_dt = batch_end_dt
                batch_num += 1
            
            print(f"Processing {total_batches} batches of {batch_size} {interval_minutes}-minute interval(s) each...")
            
            if self.parallel_workers > 1:
                print(f"Using {self.parallel_workers} parallel workers")
            
            # Track batch processing time
            batch_start_time = time.perf_counter()
            
            if dry_run:
                # Dry run - just show queries
                for batch_num, batch_start, batch_end in batches:
                    query = self.create_aggregation_query(batch_start, batch_end, source_table, dest_table, time_function, level)
                    print(f"\033[94mBatch {batch_num}/{total_batches} - Query:\033[0m")
                    print(query)
                return True
            
            # Reset progress tracking
            self.completed_batches = 0
            self.failed_batches = 0
            
            if self.parallel_workers <= 1:
                # Sequential execution
                for batch_num, batch_start, batch_end in batches:
                    success, _ = self._execute_batch(batch_num, total_batches, batch_start, batch_end,
                                                    source_table, dest_table, time_function, level)
                    if not success:
                        return False
            else:
                # Parallel execution
                with ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
                    # Submit all batches
                    futures = []
                    for batch_num, batch_start, batch_end in batches:
                        future = executor.submit(self._execute_batch, batch_num, total_batches, 
                                               batch_start, batch_end, source_table, dest_table, 
                                               time_function, level)
                        futures.append(future)
                    
                    # Wait for all to complete
                    for future in as_completed(futures):
                        success, result = future.result()
                        if not success:
                            # Don't immediately fail - let other batches complete
                            pass
                
                if self.failed_batches > 0:
                    print(f"\n\033[91m{self.failed_batches} out of {total_batches} batches failed\033[0m")
                    return False
            
            # Calculate batch processing time
            batch_end_time = time.perf_counter()
            batch_total_time = batch_end_time - batch_start_time
            
            # Format time appropriately
            if batch_total_time < 60:
                time_str = f"{batch_total_time:.2f} seconds"
            elif batch_total_time < 3600:
                time_str = f"{batch_total_time/60:.2f} minutes"
            else:
                time_str = f"{batch_total_time/3600:.2f} hours"
            
            print(f"\n\033[92mAll {total_batches} batches completed successfully in {time_str}!\033[0m")
            return True
    
    def check_for_duplicates(self, table: str, start_time: str, end_time: str) -> int:
        """Check for duplicate records in the destination table"""
        query = f"""
        SELECT count() as cnt, count(distinct time, FlowDirection, DeviceSiteRegion, DeviceSiteName, 
               DeviceSerial, EgressIfWanType, EgressSpName, DeviceAndEgressIfTagSetId, 
               EgressIfIndex, EgressIfName, IngressIfWanType, IngressSpName, 
               DeviceAndIngressIfTagSetId, IngressIfIndex, IngressIfName, Dscp, 
               ApplicationGroupName, ApplicationName, DestCountryName, DestSiteName, 
               SourceCountryName, SourceSiteName) as unique_cnt
        FROM {table}
        WHERE time >= '{start_time}'
          AND time < '{end_time}'
        """
        
        try:
            result, _ = self.execute_query(query)
            parts = result.strip().split('\t')
            if len(parts) == 2:
                total = int(parts[0])
                unique = int(parts[1])
                return total - unique
            return 0
        except Exception as e:
            print(f"\033[91mFailed to check duplicates: {e}\033[0m")
            return -1
    
    def delete_range(self, table: str, start_time: str, end_time: str, 
                    dry_run: bool = False) -> bool:
        """Delete data in a specific time range from a table"""
        query = f"""
        ALTER TABLE {table}
        DELETE WHERE time >= '{start_time}' AND time < '{end_time}'
        """
        
        if dry_run:
            print("\033[94mDry run - DELETE query:\033[0m")
            print(query)
            return True
        
        try:
            print(f"Deleting data from {table} between {start_time} and {end_time}...")
            self.execute_query(query)
            print("\033[92mDelete initiated (may take time to complete in background)\033[0m")
            return True
        except Exception as e:
            print(f"\033[91mDelete failed: {e}\033[0m")
            return False


def parse_time_range(range_str: str) -> Tuple[str, str]:
    """
    Parse time range string into start and end times
    
    Formats:
    - "2024-01-01 00:00:00,2024-01-02 00:00:00" - explicit range
    - "today" - today's data
    - "yesterday" - yesterday's data
    - "last-hour" - last complete hour
    - "last-24h" - last 24 hours
    """
    now = datetime.now()
    
    if ',' in range_str:
        # Explicit range
        parts = range_str.split(',')
        if len(parts) != 2:
            raise ValueError("Invalid time range format. Use 'start,end' format")
        return parts[0].strip(), parts[1].strip()
    
    elif range_str == 'today':
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
        return start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')
    
    elif range_str == 'yesterday':
        yesterday = now - timedelta(days=1)
        start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')
    
    elif range_str == 'last-hour':
        end = now.replace(minute=0, second=0, microsecond=0)
        start = end - timedelta(hours=1)
        return start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')
    
    elif range_str == 'last-24h':
        end = now
        start = end - timedelta(hours=24)
        return start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')
    
    else:
        raise ValueError(f"Unknown time range format: {range_str}")


def main():
    """Main entry point"""
    # Track script start time
    script_start_time = time.perf_counter()
    
    parser = argparse.ArgumentParser(
        description='Aggregate ClickHouse flow data at different time intervals (1m, 5m, 60m, 360m)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Aggregate raw data to 1-minute intervals (default)
  %(prog)s -H clickhouse.example.com --time-range yesterday
  
  # Aggregate 1-minute data to 5-minute intervals
  %(prog)s -H clickhouse.example.com --time-range yesterday --level 5m
  
  # Aggregate 5-minute data to 60-minute intervals
  %(prog)s -H clickhouse.example.com --time-range yesterday --level 60m
  
  # Aggregate 60-minute data to 360-minute (6-hour) intervals
  %(prog)s -H clickhouse.example.com --time-range yesterday --level 360m
  
  # Run all aggregation levels in sequence
  %(prog)s -H clickhouse.example.com --time-range yesterday --all-levels
  
  # Batch by 60 intervals (60 minutes for 1m level, 300 minutes for 5m level)
  %(prog)s -H clickhouse.example.com --time-range yesterday --batch-size 60
  
  # Parallel processing with 4 workers, 120 intervals per batch
  %(prog)s -H clickhouse.example.com --time-range yesterday --batch-size 120 --parallel 4
  
  # Dry run to see queries without executing
  %(prog)s -H clickhouse.example.com --time-range today --level 5m --dry-run
  
  # Check for duplicates in destination table
  %(prog)s -H clickhouse.example.com --time-range yesterday --level 5m --check-duplicates
  
  # Delete and re-aggregate (useful for fixing duplicates)
  %(prog)s -H clickhouse.example.com --time-range yesterday --level 5m --delete-first
  
  # Use HTTPS with authentication
  %(prog)s -H secure.clickhouse.com --https -u myuser -P mypass --time-range last-hour
  
  # Custom source and destination tables with specific level
  %(prog)s -H clickhouse.example.com --source-table mydb.raw_flows \\
    --dest-table mydb.aggregated_flows --level 5m --time-range today
  
  # Use site IP mapping from CSV file
  %(prog)s -H clickhouse.example.com --time-range yesterday \\
    --site-mapping LiveAction_sites.csv
        """
    )
    
    # Connection options
    parser.add_argument('-H', '--host', default='localhost',
                      help='ClickHouse host (default: localhost)')
    parser.add_argument('-p', '--port', type=int, default=8123,
                      help='ClickHouse port (default: 8123)')
    parser.add_argument('-u', '--user', default='default',
                      help='ClickHouse user (default: default)')
    parser.add_argument('-P', '--password', default='',
                      help='ClickHouse password (default: empty)')
    parser.add_argument('-d', '--database', default='livenx_flowdb',
                      help='Database to use (default: livenx_flowdb)')
    parser.add_argument('-t', '--timeout', type=int, default=300,
                      help='Query timeout in seconds (default: 300)')
    
    # SSL options
    parser.add_argument('--https', action='store_true',
                      help='Use HTTPS for secure connection')
    parser.add_argument('--no-verify-ssl', action='store_true',
                      help='Disable SSL certificate verification (insecure)')
    parser.add_argument('--verify-hostname', action='store_true',
                      help='If verifying SSL certificate, also verify hostname (more secure)')
    parser.add_argument('--ca-cert',
                      help='Path to CA certificate file for SSL verification')
    parser.add_argument('--client-cert',
                      help='Path to client certificate for mutual TLS')
    parser.add_argument('--client-key',
                      help='Path to client key for mutual TLS')
    
    # Aggregation options
    parser.add_argument('--time-range', required=True,
                      help='Time range to aggregate (e.g., "yesterday", "today", "last-hour", "2024-01-01 00:00:00,2024-01-02 00:00:00")')
    parser.add_argument('--level', choices=['1m', '5m', '60m', '360m'],
                      default='1m',
                      help='Aggregation level: 1m (raw→1min), 5m (1min→5min), 60m (5min→60min), 360m (60min→6hour) (default: 1m)')
    parser.add_argument('--all-levels', action='store_true',
                      help='Run all aggregation levels in sequence (1m, 5m, 60m, 360m)')
    parser.add_argument('--source-table',
                      help='Custom source table (uses predefined table if not specified)')
    parser.add_argument('--dest-table',
                      help='Custom destination table (uses predefined table if not specified)')
    parser.add_argument('--batch-size', type=int, default=0,
                      help='Process in batches of N aggregation intervals (0 for no batching)')
    parser.add_argument('--parallel', type=int, default=1,
                      help='Number of parallel workers for batch processing (default: 1)')
    
    # Site mapping options
    parser.add_argument('--site-mapping', 
                      help='CSV file with site name to IP range mappings (e.g., LiveAction_sites.csv)')
    
    # Action options
    parser.add_argument('--dry-run', action='store_true',
                      help='Show queries without executing them')
    parser.add_argument('--check-duplicates', action='store_true',
                      help='Check for duplicate records in destination table')
    parser.add_argument('--delete-first', action='store_true',
                      help='Delete existing data in time range before aggregating')
    parser.add_argument('--info', action='store_true',
                      help='Show table information and exit')
    
    args = parser.parse_args()
    
    # Function to format runtime
    def format_runtime(seconds):
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.2f} hours"
    
    # Parse time range
    try:
        start_time, end_time = parse_time_range(args.time_range)
    except ValueError as e:
        print(f"\033[91mError: {e}\033[0m", file=sys.stderr)
        print(f"\033[94mTotal runtime: {format_runtime(time.perf_counter() - script_start_time)}\033[0m")
        sys.exit(1)
    
    # Determine aggregation levels to run
    if args.all_levels:
        levels_to_run = ['1m', '5m', '60m', '360m']
    else:
        # Use the specified level even with custom tables
        levels_to_run = [args.level]
    
    # Create aggregator instance
    aggregator = ClickHouseAggregator(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
        timeout=args.timeout,
        use_https=args.https,
        verify_ssl=not args.no_verify_ssl,
        verify_hostname=args.verify_hostname,
        ca_cert=args.ca_cert,
        client_cert=args.client_cert,
        client_key=args.client_key,
        parallel_workers=args.parallel,
        site_mapping_file=args.site_mapping
    )
    
    # Print configuration
    print("\033[92mClickHouse Aggregation Tool\033[0m")
    print("=" * 50)
    protocol = "https" if args.https else "http"
    print(f"Server: {protocol}://{args.host}:{args.port}/{args.database}")
    if args.source_table and args.dest_table:
        print(f"Custom aggregation:")
        print(f"  Source: {args.source_table}")
        print(f"  Destination: {args.dest_table}")
        if args.level and args.level in AGGREGATION_LEVELS:
            print(f"  Using {args.level} time intervals ({AGGREGATION_LEVELS[args.level]['interval_minutes']} minutes)")
    elif args.all_levels:
        print(f"Running all aggregation levels: {', '.join(levels_to_run)}")
    else:
        level_config = AGGREGATION_LEVELS.get(args.level)
        if level_config:
            print(f"Aggregation level: {args.level} - {level_config['description']}")
            print(f"  Source: {level_config['source']}")
            print(f"  Destination: {level_config['dest']}")
    print(f"Time range: {start_time} to {end_time}")
    if args.batch_size > 0:
        # Get interval based on level (works for both custom and predefined tables)
        if args.level and args.level in AGGREGATION_LEVELS:
            interval_minutes = AGGREGATION_LEVELS[args.level]['interval_minutes']
            print(f"Batch size: {args.batch_size} x {interval_minutes}-minute intervals = {args.batch_size * interval_minutes} minutes per batch")
        elif args.all_levels:
            # Use 1m as default for all-levels
            interval_minutes = AGGREGATION_LEVELS['1m']['interval_minutes']
            print(f"Batch size: {args.batch_size} x {interval_minutes}-minute intervals = {args.batch_size * interval_minutes} minutes per batch (for 1m level)")
        else:
            # No level specified, default to 1-minute
            print(f"Batch size: {args.batch_size} x 1-minute intervals = {args.batch_size} minutes per batch")
        if args.parallel > 1:
            print(f"Parallel workers: {args.parallel}")
    print()
    
    # Test connection
    print("Testing connection... ", end='')
    if aggregator.test_connection():
        print("\033[92mOK\033[0m")
    else:
        print("\033[91mFAILED\033[0m")
        print(f"\033[94mTotal runtime: {format_runtime(time.perf_counter() - script_start_time)}\033[0m")
        sys.exit(1)
    
    # Show table info if requested
    if args.info:
        print("\n\033[94mTable Information:\033[0m")
        
        if args.source_table and args.dest_table:
            # Custom tables
            source_count = aggregator.get_table_count(args.source_table)
            source_min, source_max = aggregator.get_date_range(args.source_table)
            print(f"\nSource table: {args.source_table}")
            if source_count >= 0:
                print(f"  Row count: {source_count:,}")
            if source_min and source_max:
                print(f"  Date range: {source_min} to {source_max}")
            
            dest_count = aggregator.get_table_count(args.dest_table)
            dest_min, dest_max = aggregator.get_date_range(args.dest_table)
            print(f"\nDestination table: {args.dest_table}")
            if dest_count >= 0:
                print(f"  Row count: {dest_count:,}")
            if dest_min and dest_max:
                print(f"  Date range: {dest_min} to {dest_max}")
        else:
            # Show info for all levels
            for level_name, level_config in AGGREGATION_LEVELS.items():
                print(f"\n{level_name} aggregation: {level_config['description']}")
                
                # Source info
                source_count = aggregator.get_table_count(level_config['source'])
                if source_count >= 0:
                    print(f"  Source ({level_config['source']}): {source_count:,} rows")
                
                # Dest info
                dest_count = aggregator.get_table_count(level_config['dest'])
                if dest_count >= 0:
                    print(f"  Dest ({level_config['dest']}): {dest_count:,} rows")
        
        print(f"\n\033[94mTotal runtime: {format_runtime(time.perf_counter() - script_start_time)}\033[0m")
        sys.exit(0)
    
    # Process each aggregation level
    overall_success = True
    
    for level in levels_to_run:
        # Check if using custom tables
        if args.source_table and args.dest_table:
            # Using custom tables
            source_table = args.source_table
            dest_table = args.dest_table
            
            # Use level configuration for time function if level is specified
            if level and level in AGGREGATION_LEVELS:
                level_config = AGGREGATION_LEVELS[level]
                time_function = level_config['time_function']
                level_desc = f"Custom aggregation with {level} intervals"
            else:
                time_function = 'toStartOfMinute'  # Default for custom tables
                level_desc = "Custom aggregation"
        else:
            # Using predefined level
            if not level or level not in AGGREGATION_LEVELS:
                print(f"\033[91mError: Unknown aggregation level {level}\033[0m")
                print(f"\033[94mTotal runtime: {format_runtime(time.perf_counter() - script_start_time)}\033[0m")
                sys.exit(1)
            
            level_config = AGGREGATION_LEVELS[level]
            source_table = level_config['source']
            dest_table = level_config['dest']
            time_function = level_config['time_function']
            level_desc = level_config['description']
            
            if len(levels_to_run) > 1:
                print(f"\n\033[94m=== Processing {level} aggregation: {level_desc} ===\033[0m")
        
        # Check for duplicates if requested
        if args.check_duplicates:
            print("\nChecking for duplicates in destination table...")
            duplicates = aggregator.check_for_duplicates(dest_table, start_time, end_time)
            if duplicates > 0:
                print(f"\033[93mFound {duplicates:,} duplicate records in time range\033[0m")
            elif duplicates == 0:
                print("\033[92mNo duplicates found in time range\033[0m")
            else:
                print("\033[91mFailed to check for duplicates\033[0m")
            
            if not args.delete_first and not args.dry_run and len(levels_to_run) == 1:
                continue
        
        # Delete existing data if requested
        if args.delete_first and not args.dry_run:
            print(f"\n\033[93mDeleting existing data from {dest_table}...\033[0m")
            if not aggregator.delete_range(dest_table, start_time, end_time, args.dry_run):
                print("\033[91mFailed to delete existing data\033[0m")
                overall_success = False
                continue
            print("Waiting 5 seconds for delete to process...")
            time.sleep(5)
        
        # Run aggregation
        print(f"\n\033[94mStarting {level_desc}...\033[0m")
        success = aggregator.run_aggregation(
            start_time=start_time,
            end_time=end_time,
            source_table=source_table,
            dest_table=dest_table,
            batch_size=args.batch_size,
            dry_run=args.dry_run,
            time_function=time_function,
            level=level
        )
        
        if not success:
            overall_success = False
            if len(levels_to_run) > 1:
                print(f"\033[91mFailed {level} aggregation, skipping remaining levels\033[0m")
                break
    
    # Calculate total runtime
    script_end_time = time.perf_counter()
    total_runtime = script_end_time - script_start_time
    
    if overall_success:
        print("\n" + "=" * 50)
        if len(levels_to_run) > 1:
            print(f"\033[92mAll {len(levels_to_run)} aggregation levels completed successfully!\033[0m")
        else:
            print("\033[92mAggregation completed successfully!\033[0m")
        print(f"\033[94mTotal runtime: {format_runtime(total_runtime)}\033[0m")
    else:
        print("\n" + "=" * 50)
        print("\033[91mAggregation failed!\033[0m")
        print(f"\033[94mTotal runtime: {format_runtime(total_runtime)}\033[0m")
        sys.exit(1)


if __name__ == '__main__':
    main()

