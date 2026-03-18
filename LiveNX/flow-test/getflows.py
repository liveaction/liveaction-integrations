#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import ipaddress
import json
import logging
import logging.handlers
import os
import string
import time

import requests
from http.client import HTTPConnection


#############################################################
# Startup
#############################################################

SCRIPT_START = time.time()

HTTPConnection.debuglevel = 0
requests.packages.urllib3.disable_warnings()

REQUEST_TIMEOUT = 30
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "16"))
REPORT_POLL_INTERVAL = float(os.getenv("REPORT_POLL_INTERVAL", "1"))
REPORT_WAIT_TIMEOUT = int(os.getenv("REPORT_WAIT_TIMEOUT", "300"))

#############################################################
# Required Environment Variables
#############################################################

NXSERVER = os.getenv("NX_SERVER")
APIKEY = os.getenv("API_KEY")
FLEX_CRITERIA = os.getenv("FLEX_CRITERIA")

if not NXSERVER:
    raise ValueError("NX_SERVER environment variable is required")

if not APIKEY:
    raise ValueError("API_KEY environment variable is required")

if not FLEX_CRITERIA:
    raise ValueError("FLEX_CRITERIA environment variable is required")

#############################################################
# Optional Environment Variables
#############################################################

FLOW_NETWORK_FILE_PATH = os.getenv(
    "FLOW_NETWORK_FILE_PATH",
    "/opt/app/Files/FLOW_Networks_rfc10.txt"
)

LOG_FILE_PATH = os.getenv(
    "LOG_FILE_PATH",
    "/opt/app/Files/LiveNX_FLOWl200.log"
)

OUTPUT_JSON_FILE = os.getenv(
    "OUTPUT_JSON_FILE",
    "/opt/app/Files/LiveNX_Results_l200.json"
)

REPORT_DATA_SOURCE = os.getenv(
    "REPORT_DATA_SOURCE",
    "flowstore_v2"
).strip().lower()

SYSLOG_SERVER = os.getenv("SYSLOG_SERVER")
SYSLOG_PORT = os.getenv("SYSLOG_PORT")

if REPORT_DATA_SOURCE not in ("flowstore", "flowstore_v2"):
    raise ValueError("REPORT_DATA_SOURCE must be 'flowstore' or 'flowstore_v2'")

#############################################################
# Helpers
#############################################################

def build_queue_url(nxserver):
    return "https://{0}:8093/v1/reports/queue".format(nxserver)


def build_flow_limit_url(nxserver):
    return "https://{0}:8093/v1/reports/flow/limit".format(nxserver)


def build_headers(apikey):
    return {
        "accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Authorization": "Bearer {0}".format(apikey),
        "Content-Type": "application/json"
    }


def configure_logger():
    logger = logging.getLogger("LiveNX_FLOW")
    logger.setLevel(logging.INFO)
    logger.handlers = []

    formatter = logging.Formatter(
        'LiveNX_FLOW: { "timestamp":"%(asctime)s",'
        '"pathName":"%(pathname)s","functionName":"%(funcName)s",'
        '"levelName":"%(levelname)s","lineNo":"%(lineno)d",'
        '"message":"%(message)s"}'
    )

    file_handler = logging.FileHandler(LOG_FILE_PATH)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if SYSLOG_SERVER and SYSLOG_PORT:
        remote_handler = logging.handlers.DatagramHandler(
            SYSLOG_SERVER,
            int(SYSLOG_PORT)
        )
        remote_handler.setFormatter(formatter)
        # logger.addHandler(remote_handler)

    return logger


def create_session(headers):
    session = requests.Session()
    session.headers.update(headers)
    return session


def get_response_message(response):
    try:
        payload = response.json()
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        for key in ("userMessage", "message", "error"):
            value = payload.get(key)
            if value:
                return str(value)

    body = response.text.strip()
    if not body:
        return ""

    return body[:200]


#############################################################
# API
#############################################################

def set_flow_limit(session):
    payload = {"maxReturnSize": 15000}

    response = session.put(
        build_flow_limit_url(NXSERVER),
        verify=False,
        data=json.dumps(payload),
        timeout=REQUEST_TIMEOUT
    )
    response.raise_for_status()


def submit_report(session, payload):
    response = session.post(
        build_queue_url(NXSERVER),
        verify=False,
        data=json.dumps(payload),
        timeout=REQUEST_TIMEOUT
    )
    response.raise_for_status()
    return response.json()


def wait_for_report(session, result_url):
    start = time.time()
    last_error = ""

    while True:
        elapsed = time.time() - start
        if elapsed >= REPORT_WAIT_TIMEOUT:
            message = (
                "Timed out waiting for report after {}s".format(
                    round(elapsed, 2)
                )
            )
            if last_error:
                message = "{}. Last response: {}".format(message, last_error)
            raise TimeoutError(message)

        response = session.get(
            result_url,
            verify=False,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 400:
            last_error = get_response_message(response)
            print("Report's still processing...")
            time.sleep(REPORT_POLL_INTERVAL)
            continue

        response.raise_for_status()

        result_json = response.json()

        if result_json.get("userMessage"):
            last_error = str(result_json["userMessage"])
            print("Report's still processing...")
            time.sleep(REPORT_POLL_INTERVAL)
            continue

        print("Report ready in {}s".format(round(time.time() - start, 2)))
        return result_json


#############################################################
# FLOW Network Index (FAST LOOKUP)
#############################################################

def first_octet(ip_int):
    return (ip_int >> 24) & 0xFF


def load_flow_index(path, logger):
    network_index = []
    bucket = {}

    with open(path, "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) != 3:
                continue

            net_str, name, threshold = parts

            try:
                net = ipaddress.IPv4Network(net_str, strict=False)
            except Exception:
                continue

            try:
                threshold_val = float(threshold)
                invalid = False
            except Exception:
                threshold_val = None
                invalid = True

            start = int(net.network_address)
            end = int(net.broadcast_address)

            entry = {
                "start": start,
                "end": end,
                "name": name,
                "threshold": threshold,
                "threshold_val": threshold_val,
                "invalid": invalid
            }

            network_index.append(entry)

            o1 = first_octet(start)
            o2 = first_octet(end)

            for o in range(o1, o2 + 1):
                bucket.setdefault(o, []).append(entry)

    return network_index, bucket


#############################################################
# Processing
#############################################################

def clean_ip(val):
    return val.strip(
        string.ascii_letters + string.whitespace + string.punctuation
    )


def process_record(record, bucket, logger):
    try:
        src_ip = clean_ip(record["data"][0]["value"])
        src_port = record["data"][2]["value"]
        dst_ip = clean_ip(record["data"][3]["value"])
        dst_port = record["data"][5]["value"]
        bitrate = round(record["data"][12]["value"], 3)
    except Exception:
        return

    try:
        ip_obj = ipaddress.IPv4Address(dst_ip)
        ip_int = int(ip_obj)
    except Exception:
        return

    candidates = bucket.get(first_octet(ip_int), [])

    for net in candidates:
        if not (net["start"] <= ip_int <= net["end"]):
            continue

        if net["invalid"]:
            logger.info(
                "IP %s matched %s but invalid threshold %s",
                dst_ip,
                net["name"],
                net["threshold"]
            )
            continue

        if bitrate > net["threshold_val"]:
            logger.info(
                "ALERT src=%s:%s dst=%s:%s bitrate=%s exceeded %s (%s)",
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                bitrate,
                net["name"],
                net["threshold"]
            )


def process_records(records, bucket, logger):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        list(ex.map(lambda r: process_record(r, bucket, logger), records))


#############################################################
# Main
#############################################################

def main():
    logger = configure_logger()

    headers = build_headers(APIKEY)
    session = create_session(headers)

    payload = {
        "name": "",
        "reports": [{
            "reportId": {"category": "flow", "id": "79"},
            "parameters": {
                "deviceSerial": "ALL_DEVICES_SERIAL",
                "direction": "outbound",
                "executionType": "timeseries",
                "flexSearch": FLEX_CRITERIA,
                "reportDataSource": REPORT_DATA_SOURCE,
                "sortBy": "BIT_RATE",
                "binDuration": "5min",
                "useFlowReportLimit": True
            }
        }],
        "clientTimeParameters": {"relativeQueryTime": 1200}
    }

    network_list, bucket = load_flow_index(FLOW_NETWORK_FILE_PATH, logger)

    set_flow_limit(session)

    job = submit_report(session, payload)
    result_url = job["jobInfo"]["result"]
    print(result_url)

    result = wait_for_report(session, result_url)

    summary = result["results"][0]["results"][0]["summary"]["summaryData"]

    with open(OUTPUT_JSON_FILE, "w") as f:
        json.dump(summary, f, indent=4)

    print("Processing {} records vs {} networks".format(
        len(summary), len(network_list)
    ))

    start = time.time()

    process_records(summary, bucket, logger)

    print("Processing time:", round(time.time() - start, 2))
    print("Total runtime:", round(time.time() - SCRIPT_START, 2))


if __name__ == "__main__":
    main()
