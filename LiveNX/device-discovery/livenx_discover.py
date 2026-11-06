#!/usr/bin/env python3
"""Run LiveNX network discovery on IP addresses/ranges and print the discovered devices as CSV on stdout.

Uses POST /v1/deviceDiscovery/start/ipRange and polls the job until it finishes (see livenx_openapi.json).
This only discovers devices; it does not add them to LiveNX. Standard library only (Python 3.9+).

Targets are positional arguments and/or one per line in --file ('-' reads stdin; '#' starts a comment).
Anything LiveNX accepts as an address/range is passed through unchanged, e.g. 10.0.0.5, 10.0.0.1-10.0.0.50,
10.0.1.0/24.

Examples:
  ./livenx_discover.py --host 10.4.205.50 --api-key '<key>' 10.0.0.5 10.0.1.0/24
  ./livenx_discover.py --host 10.4.205.50 --api-key '<key>' --file targets.txt --community public
"""
import argparse
import csv
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

TERMINAL_STATUSES = ("SUCCESS", "ERROR", "CANCELLED")


class LiveNx:
  def __init__(self, host, port, api_key, verify_tls):
    self.base = "https://%s:%d/v1" % (host, port)
    self.api_key = api_key
    self.context = ssl.create_default_context()
    if not verify_tls:
      self.context.check_hostname = False
      self.context.verify_mode = ssl.CERT_NONE

  def call(self, method, path, body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(self.base + path, data=data, method=method, headers={
      "Authorization": "Bearer " + self.api_key,
      "Accept": "application/json",
      "Content-Type": "application/json",
    })
    try:
      with urllib.request.urlopen(request, context=self.context, timeout=60) as response:
        return json.load(response)
    except urllib.error.HTTPError as e:
      detail = e.read().decode("utf-8", "replace")[:500]
      sys.exit("HTTP %d %s from %s %s: %s" % (e.code, e.reason, method, path, detail))
    except (urllib.error.URLError, OSError) as e:
      sys.exit("Failed to reach LiveNX API: %s" % e)


def read_targets(args):
  targets = list(args.targets)
  if args.file:
    lines = sys.stdin if args.file == "-" else open(args.file)
    with lines:
      for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
          targets.append(line)
  return targets


def credential(args):
  if args.community:
    return {"type": "manual", "credential": {
      "port": args.snmp_port,
      "snmpVersion": "2c",
      "settings": {"snmpCommunity": args.community},
    }}
  return {"type": "snmpCredentialsStore", "credential": {}}


def pick_node(api, node_id, node_ip):
  if node_id:
    return node_id
  nodes = api.call("GET", "/nodes").get("nodes", [])
  if node_ip:
    matches = [n for n in nodes if n.get("ipAddress") == node_ip]
    if not matches:
      sys.exit("No node with IP %s (known: %s)" % (node_ip, ", ".join(str(n.get("ipAddress")) for n in nodes)))
    return matches[0]["id"]
  local = [n for n in nodes if n.get("local")]
  if not local:
    sys.exit("No local node found; specify one with --node-ip or --node-id")
  return local[0]["id"]


def main():
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                   epilog="\n".join(__doc__.splitlines()[2:]))
  parser.add_argument("targets", nargs="*", help="IP addresses or ranges to discover")
  parser.add_argument("--file", help="file with one IP/range per line ('-' for stdin)")
  parser.add_argument("--host", required=True, help="LiveNX API server IP or hostname")
  parser.add_argument("--port", type=int, default=8093, help="LiveNX API port (default: 8093)")
  parser.add_argument("--api-key", required=True, help="LiveNX API key")
  node = parser.add_mutually_exclusive_group()
  node.add_argument("--node-ip", help="IP of the node to run discovery from (default: the local server node)")
  node.add_argument("--node-id", help="ID of the node to run discovery from, instead of --node-ip")
  parser.add_argument("--community", help="SNMPv2c community string; default is the LiveNX SNMP credentials store")
  parser.add_argument("--snmp-port", type=int, default=161, help="SNMP port with --community (default: 161)")
  parser.add_argument("--poll-interval", type=float, default=3, help="seconds between status polls (default: 3)")
  parser.add_argument("--timeout", type=float, default=1800, help="give up waiting after this many seconds")
  parser.add_argument("--verify-tls", action="store_true",
                      help="verify the server certificate (off by default; LiveNX uses a self-signed cert)")
  parser.add_argument("--dry-run", action="store_true", help="print the request that would be sent and exit")
  args = parser.parse_args()

  targets = read_targets(args)
  if not targets:
    parser.error("no IPs/ranges given (use positional arguments or --file)")

  api = LiveNx(args.host, args.port, args.api_key, args.verify_tls)
  request = {
    "ipRanges": targets,
    "nodeId": pick_node(api, args.node_id, args.node_ip),
    "snmpCredential": credential(args),
    "deviceIdentificationType": "DISCOVERY",
  }
  if args.dry_run:
    if args.community:
      request["snmpCredential"]["credential"]["settings"]["snmpCommunity"] = "***"
    print(json.dumps(request, indent=2), file=sys.stderr)
    return

  job_id = api.call("POST", "/deviceDiscovery/start/ipRange", request)["jobId"]
  print("Started discovery job %s on %d target(s)" % (job_id, len(targets)), file=sys.stderr)

  deadline = time.time() + args.timeout
  while True:
    job = api.call("GET", "/deviceDiscovery/jobs/" + job_id)
    print("  status=%s attempted=%s/%s discovered=%s" % (
      job.get("status"), job.get("attemptedCount"), job.get("expectedCount"), job.get("discoveredCount")),
      file=sys.stderr)
    if job.get("status") in TERMINAL_STATUSES:
      break
    if time.time() > deadline:
      sys.exit("Timed out waiting for job %s (still running on the server)" % job_id)
    time.sleep(args.poll_interval)

  results = api.call("GET", "/deviceDiscovery/jobs/%s/results" % job_id)
  writer = csv.writer(sys.stdout, lineterminator="\n")
  writer.writerow(["serial", "hostName", "systemName", "primaryIp", "vendor", "model", "osVersion"])
  for node in results.get("results", []):
    for device in node.get("devices", []):
      info = device.get("deviceInfo") or {}
      product = info.get("vendorProduct") or {}
      writer.writerow([
        device.get("resultId", info.get("serial", "")),
        info.get("hostName", ""),
        info.get("systemName", ""),
        info.get("address", ""),
        (product.get("vendor") or {}).get("vendorName", ""),
        product.get("model", ""),
        info.get("osVersionString", ""),
      ])
  if job.get("status") != "SUCCESS":
    sys.exit("Discovery job finished with status %s" % job.get("status"))


if __name__ == "__main__":
  main()
