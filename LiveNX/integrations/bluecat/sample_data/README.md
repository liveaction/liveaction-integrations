# Sample Data for IPAM Device Import

This directory contains sample CSV files that can be used to test and populate the ClickHouse `ipam_devices` table with realistic network device data.

## CSV Files

### corporate_network.csv
Contains 31 sample records from a corporate network (10.255.1.110-140) including:
- Network infrastructure (routers, switches, firewalls)
- Servers (domain controllers, application servers)
- User devices (laptops, desktops, tablets)
- IoT devices (cameras, sensors, VoIP phones)
- Network services (printers, access points, UPS)
- Mix of static IPs, DHCP allocations, and reserved addresses
- Active and expired DHCP leases

## Data Fields

Each CSV file contains the following columns:
- `network_cidr`: Network in CIDR notation
- `ip`: IP address
- `hostname`: Device hostname
- `fqdn`: Fully qualified domain name
- `mac`: MAC address
- `state`: IP state (STATIC, DHCP_ALLOCATED, DHCP_RESERVED, DHCP_FREE)
- `ip_version`: IP version (IPv4/IPv6)
- `ptr_record`: PTR record for reverse DNS
- `bam_network_id`: BlueCat network entity ID
- `bam_ip_entity_id`: BlueCat IP entity ID
- `lease_start`: DHCP lease start time (ISO format)
- `lease_end`: DHCP lease end time (ISO format)
- `lease_state`: DHCP lease state (ACTIVE, EXPIRED)
- `source_system`: Source system identifier
- `tenant`: Tenant identifier
- `document`: Denormalized text for full-text search
- `snapshot_at`: Snapshot timestamp
- `_ingested_at`: Ingestion timestamp
- `_version`: Version for deduplication

## Usage

### Direct Import to ClickHouse

Use the provided import script:

```bash
# First, configure your ClickHouse connection in .env file
cp ../env.sample ../.env
# Edit ../.env with your ClickHouse credentials

# Import a CSV file
python3 import_csv.py corporate_network.csv
```

### Using ClickHouse Client

```bash
# Using clickhouse-client
clickhouse-client --query "
INSERT INTO netops.ipam_devices
FORMAT CSVWithNames" < corporate_network.csv
```

### Manual Testing

You can also use these CSV files to:
1. Test your BlueCat import pipeline
2. Validate ClickHouse queries
3. Develop dashboards and reports
4. Test data transformations

## Sample Queries

Once imported, you can run queries like:

```sql
-- Count devices by state
SELECT state, count(*) as count
FROM netops.ipam_devices
WHERE network_cidr = '10.255.1.0/24'
GROUP BY state
ORDER BY count DESC;

-- Find all active DHCP leases
SELECT hostname, ip, mac, lease_end
FROM netops.ipam_devices
WHERE lease_state = 'ACTIVE'
  AND lease_end > now()
ORDER BY lease_end ASC;

-- List all network infrastructure
SELECT hostname, ip, state
FROM netops.ipam_devices
WHERE hostname LIKE '%sw-%'
   OR hostname LIKE '%gw-%'
   OR hostname LIKE '%fw-%'
ORDER BY ip;
```

## Generating More Sample Data

To generate additional sample data:
1. Copy an existing CSV as a template
2. Modify IP ranges, hostnames, and other fields
3. Ensure consistency in network_cidr and IP addresses
4. Update timestamps to current dates if needed
5. Maintain realistic MAC addresses for each device type