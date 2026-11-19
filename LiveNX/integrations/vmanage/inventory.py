#!/usr/bin/env python3
"""Cisco SD-WAN (vManage) inventory -> LiveNX virtual device sync."""

import os
import logging
import requests
import urllib3

from common.livenx_inventory import get_livenx_nodes, compare_livenx_device

local_logger = logging.getLogger(__name__)

vmanageHost = os.getenv("VMANAGE_API_HOST", "")
vmanagePort = os.getenv("VMANAGE_API_PORT", "8443")
vmanageUser = os.getenv("VMANAGE_API_USER", "")
vmanagePass = os.getenv("VMANAGE_API_PASSWORD", "")
vmanageVerifySsl = os.getenv("VMANAGE_API_VERIFY_SSL", "false").lower() == "true"
# Optional: force every device into one LiveNX site. Default is "SDWAN-Site-<site-id>".
vmanageLivenxSite = os.getenv("VMANAGE_LIVENX_SITE", "")
# Optional: comma separated vManage device-type values to import (default: edges only).
vmanageDeviceTypes = [t.strip().lower() for t in os.getenv("VMANAGE_DEVICE_TYPES", "vedge").split(",") if t.strip()]
# Optional: only import devices vManage reports as reachable.
vmanageOnlyReachable = os.getenv("VMANAGE_ONLY_REACHABLE", "false").lower() == "true"
liveNxTargetIP = os.getenv("LIVENX_TARGET_IP", "")

REQUEST_TIMEOUT = 60

if not vmanageVerifySsl:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def vmanage_login():
    """Log in to vManage and return a requests.Session ready for API calls (cookie + XSRF token)."""
    base_url = f"https://{vmanageHost}:{vmanagePort}"
    session = requests.Session()
    session.verify = vmanageVerifySsl

    resp = session.post(f"{base_url}/j_security_check",
                        data={"j_username": vmanageUser, "j_password": vmanagePass},
                        timeout=REQUEST_TIMEOUT)
    # vManage answers a failed login with 200 and an HTML login page and no JSESSIONID cookie.
    if resp.status_code != 200 or "JSESSIONID" not in session.cookies or resp.text.strip().startswith("<"):
        raise RuntimeError("vManage login failed (check VMANAGE_API_USER / VMANAGE_API_PASSWORD)")

    # 19.2+ requires an XSRF token on non-GET calls; older versions return 404, which is fine.
    token_resp = session.get(f"{base_url}/dataservice/client/token", timeout=REQUEST_TIMEOUT)
    if token_resp.status_code == 200 and token_resp.text:
        session.headers.update({"X-XSRF-TOKEN": token_resp.text})
    return session


def vmanage_logout(session):
    try:
        session.get(f"https://{vmanageHost}:{vmanagePort}/logout?nocache=1", timeout=REQUEST_TIMEOUT)
    except requests.RequestException as err:
        local_logger.debug(f"vManage logout failed: {err}")


def get_vmanage_inventory():
    """Return the list of device dicts from vManage GET /dataservice/device."""
    session = vmanage_login()
    try:
        resp = session.get(f"https://{vmanageHost}:{vmanagePort}/dataservice/device", timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        devices = resp.json().get("data", [])
    finally:
        vmanage_logout(session)
    local_logger.info(f"vManage returned {len(devices)} devices")
    return devices


def _first(device, *keys):
    for key in keys:
        value = device.get(key)
        if value not in (None, ""):
            return value
    return ""


def create_livenx_device_from_vmanage_device(nodeid, vmanage_device):
    """
    vManage /dataservice/device entry (relevant fields):
      {"deviceId": "1.1.1.1", "system-ip": "1.1.1.1", "host-name": "vedge-1",
       "reachability": "reachable", "status": "normal", "device-type": "vedge",
       "device-model": "vedge-cloud", "uuid": "...", "board-serial": "...",
       "site-id": "100", "version": "20.9.3", "personality": "vedge", ...}
    """
    system_ip = _first(vmanage_device, "system-ip", "deviceId")
    hostname = _first(vmanage_device, "host-name") or system_ip
    site_id = _first(vmanage_device, "site-id")
    model = _first(vmanage_device, "device-model")
    version = _first(vmanage_device, "version")
    serial = _first(vmanage_device, "board-serial", "uuid")

    description = f"Cisco SD-WAN {model}".strip()
    if version:
        description += f" v{version}"
    if serial:
        description += f" (serial {serial})"

    return {
        "nodeId": nodeid,
        "hostName": hostname,
        "systemName": hostname,
        "systemDescription": description,
        "address": system_ip,
        "site": vmanageLivenxSite or (f"SDWAN-Site-{site_id}" if site_id else "SDWAN"),
        "stringTags": "vmanage",
        "userDefinedSampleRatio": 1,
        "interfaces": [{
            "ifIndex": "0",
            "name": "system",
            "address": system_ip,
            "subnetMask": "255.255.255.255",
            "description": "vManage system IP",
            "serviceProvider": "",
            "inputCapacity": "1000000",
            "outputCapacity": "1000000",
            "wan": False,
            "xcon": False,
            "label": "",
            "stringTags": "",
        }],
    }


def map_vmanage_inventory_to_livenx_inventory(vmanage_inventory):
    """Map vManage devices to the LiveNX virtual-device payload ({'devices': [...]})."""
    nodeid = None
    for node in get_livenx_nodes():
        if node.get("ipAddress") == liveNxTargetIP:
            nodeid = node["id"]
            break
    if nodeid is None:
        raise RuntimeError(f"No LiveNX node found with ipAddress == LIVENX_TARGET_IP ({liveNxTargetIP!r})")

    devices = []
    for vmanage_device in vmanage_inventory:
        device_type = str(vmanage_device.get("device-type", "")).lower()
        if vmanageDeviceTypes and device_type not in vmanageDeviceTypes:
            continue
        if vmanageOnlyReachable and vmanage_device.get("reachability") != "reachable":
            continue
        if not _first(vmanage_device, "system-ip", "deviceId"):
            local_logger.warning(f"Skipping vManage device without system IP: {vmanage_device.get('host-name')}")
            continue
        devices.append(create_livenx_device_from_vmanage_device(nodeid, vmanage_device))
    return {"devices": devices}


def diff_vmanage_inventory(new_livenx_inventory, orig_livenx_inventory):
    """Devices in new_livenx_inventory (from vManage) that LiveNX doesn't have yet (hostName + address match)."""
    existing = orig_livenx_inventory.get("devices", [])
    return [d for d in new_livenx_inventory["devices"]
            if not any(compare_livenx_device(d, e) for e in existing)]
