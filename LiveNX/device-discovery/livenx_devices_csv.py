#!/usr/bin/env python3
"""Print the devices onboarded to LiveNX, with their primary IPs, as CSV on stdout.

Uses GET /v1/devices (see livenx_openapi.json). Standard library only (Python 3.9+).

Example:
  ./livenx_devices_csv.py --host 10.4.205.50 --port 8093 --api-key '<key>' > devices.csv
"""
import argparse
import csv
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def fetch_devices(host, port, api_key, include_historical, verify_tls):
  query = urllib.parse.urlencode({
    "includeHistorical": str(include_historical).lower(),
    "isCompactResponse": "true",
  })
  url = "https://%s:%d/v1/devices?%s" % (host, port, query)
  request = urllib.request.Request(url, headers={
    "Authorization": "Bearer " + api_key,
    "Accept": "application/json",
  })
  context = ssl.create_default_context()
  if not verify_tls:
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
  with urllib.request.urlopen(request, context=context, timeout=60) as response:
    return json.load(response).get("devices", [])


def main():
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  parser.add_argument("--host", required=True, help="LiveNX API server IP or hostname")
  parser.add_argument("--port", type=int, default=8093, help="LiveNX API port (default: 8093)")
  parser.add_argument("--api-key", required=True, help="LiveNX API key")
  parser.add_argument("--include-historical", action="store_true",
                      help="also include historical (no longer onboarded) devices")
  parser.add_argument("--verify-tls", action="store_true",
                      help="verify the server certificate (off by default; LiveNX uses a self-signed cert)")
  args = parser.parse_args()

  try:
    devices = fetch_devices(args.host, args.port, args.api_key, args.include_historical, args.verify_tls)
  except urllib.error.HTTPError as e:
    sys.exit("HTTP %d %s from LiveNX API" % (e.code, e.reason))
  except (urllib.error.URLError, OSError) as e:
    sys.exit("Failed to reach LiveNX API: %s" % e)

  writer = csv.writer(sys.stdout, lineterminator="\n")
  writer.writerow(["id", "hostName", "systemName", "primaryIp", "clientIp", "site", "vendor", "model"])
  for d in devices:
    product = d.get("vendorProduct") or {}
    vendor = (product.get("vendor") or {}).get("vendorName", "")
    writer.writerow([
      d.get("id", ""),
      d.get("hostName", ""),
      d.get("systemName", ""),
      d.get("address", ""),
      d.get("clientIp", ""),
      d.get("site", ""),
      vendor,
      product.get("model", ""),
    ])


if __name__ == "__main__":
  main()
