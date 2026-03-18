# Offline Pip Bundle

This bundle installs the Python dependencies for `device_observability_report.py`
without internet access.

Target environment:

- Ubuntu 22.04.5 LTS
- x86_64
- CPython 3.10

Contents:

- `requirements.txt`: top-level dependencies for the report
- `wheels/`: downloaded wheel files, including transitive dependencies
- `install_offline.sh`: installs from the local wheel directory only

Install:

```bash
./install_offline.sh
```

Equivalent command:

```bash
python3 -m pip install --no-index --find-links ./wheels -r requirements.txt
```

This bundle is platform- and Python-version-specific because `lz4` and
`clickhouse-cityhash` are compiled wheels. It is intended for Ubuntu 22.04.x
systems using the default Python 3.10 runtime on x86_64.
