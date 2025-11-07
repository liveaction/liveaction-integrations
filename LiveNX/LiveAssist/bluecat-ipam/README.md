# Bluecat IPAM Data for LiveAssist

To allow LiveAssist to analyze Bluecat IPAM data first follow the BAM to LiveNX integration instructions at ../../bluecat/README.md


Next, run the create_bluecat_ipam_view.sh script on LivenX.

Tnis creates a ClickHouse view that exposes BlueCat IPAM device data:

```sql
CREATE VIEW IF NOT EXISTS liveassist.BlueCat_IPAM_IP_Management_Address_Devices
AS SELECT * FROM netops.ipam_devices;
```

This script does **one thing** and does it idempotently. If the view already exists, nothing changes.

---

- The database `liveassist` **must already exist**.
- The source table `netops.ipam_devices` **must already exist** and be readable by your ClickHouse user.

> If `liveassist` or `netops.ipam_devices` don’t exist, ClickHouse will error. That’s by design—this script only creates the view.

---

## Usage

```bash
./create_bluecat_ipam_view.sh
```

---

## Quick start

```bash
# Make it executable
chmod +x create_bluecat_ipam_view.sh

# Run it (defaults usually work on a local dev setup)
./create_bluecat_ipam_view.sh
```

Expected output:

```
OK: Ensured view liveassist.BlueCat_IPAM_IP_Management_Address_Devices exists.
```

---

## Verify

Confirm the view exists and points where you think it does:

```bash
docker exec -it clickhouse-server clickhouse-client   --query "SHOW CREATE VIEW liveassist.BlueCat_IPAM_IP_Management_Address_Devices\G"
```

Optionally, run a quick count to verify the wiring:

```bash
docker exec -it clickhouse-server clickhouse-client   --query "SELECT count() FROM liveassist.BlueCat_IPAM_IP_Management_Address_Devices"
```

---

## Common failures (and straight fixes)

- **`Code: 60, DB::Exception: Database liveassist doesn't exist`**  
  Create it first:  
  
  ```bash
  docker exec -it clickhouse-server clickhouse-client     --query "CREATE DATABASE IF NOT EXISTS liveassist"
  ```

- **`Code: 60, DB::Exception: Table netops.ipam_devices doesn't exist`**  
  Create/restore the source table or fix your target DB/table.

- **`Docker container ... is not running (or not found)`**  
  Start the container or pass `--docker-container <name>`.

- **Auth errors**  
  Pass proper creds: `--ch-user` and `--ch-password`.

---

## Security notes

- Passing `--ch-password` on the command line can expose the password in shell history or process listings on some systems. Use a low-privilege user and rotate credentials regularly.
- If you need stricter hygiene, adapt the script to prompt for a password or use ClickHouse’s secure connection and config files.

---

## Exit codes

- `0` : View ensured (created or already existed)
- `≠0`: Something failed (missing DB/table, auth, container not running, etc.)

---

## Maintenance

This view is a thin veneer over `netops.ipam_devices`. If you change or drop that table, this view follows the consequences. Keep source schema ownership and view consumers aligned.
