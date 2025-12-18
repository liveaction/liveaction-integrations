import json
import sys
from pathlib import Path

import pytest
import runpy
import random
import requests


SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))

import infoblox_script as script  # noqa: E402


def test_process_consolidation_parses_ips_from_csv_fixture():
    csv_lines = SCRIPT_DIR.joinpath("livenx.csv").read_text().splitlines()
    if csv_lines and csv_lines[0].strip().lower() == "top analysis":
        csv_lines = csv_lines[1:]
    infoblox_leases = [
        {"address": "56.37.2.121", "hardware": "aa:bb:cc:dd:ee:ff"},
        {"address": "10.164.0.147", "hardware": "11:22:33:44:55:66"},
    ]

    consolidated = script.process_consolidation(csv_lines, infoblox_leases)

    assert len(consolidated) == 5
    src_ips = {entry["SRC IP (private)"] for entry in consolidated}
    assert "56.37.2.121" in src_ips
    assert "10.164.0.147" in src_ips
    # Ensure the Infoblox MAC address mapping is applied where available
    macs = {entry["SRC IP (private)"]: entry["SRC MAC"] for entry in consolidated}
    assert macs["56.37.2.121"] == "aa:bb:cc:dd:ee:ff"
    assert macs["10.164.0.147"] == "11:22:33:44:55:66"


def test_pull_nat_data_from_LiveNX_skips_top_analysis_line(monkeypatch):
    body = "Top Analysis\n" + SCRIPT_DIR.joinpath("livenx.csv").read_text()

    class FakeResponse:
        status_code = 200
        text = body

    called = {}

    def fake_get(url, headers=None, verify=None, timeout=None):
        called["url"] = url
        return FakeResponse()

    monkeypatch.setattr(script.requests, "get", fake_get)

    data = script.pull_nat_data_from_LiveNX("host", "token", 0, 1, "rid", "ds")
    assert data[0].startswith("Time,Flow Record Count")
    original_lines = SCRIPT_DIR.joinpath("livenx.csv").read_text().splitlines()
    # Response has two leading "Top Analysis" lines; one is from the fixture and one we preprended in the test.
    assert len(data) == len(original_lines) - 1



def test_script_with_mock_infoblox_api(monkeypatch):
    """
    Integration test to run main script with Infoblox API patch
 
    Note: It will run infinite due to main script polling
    """
    mock_response = {
        "result": [
            {"address": "146.112.255.155" },
            {"address": "10.164.0.147", "hardware": "14:72:33:44:55:66" },
            {"address": "10.164.0.113", "hardware": "11:32:33:44:55:66", "client_hostname":"host113.name"},
            {"address": "10.164.0.88", "hardware": "88:22:33:44:55:66", "client_hostname":"host88.name"},
            {"address": "10.164.0.101", "hardware": "10:12:33:44:55:66", "client_hostname":"host101.name"}
        ]
    }
   
    # Save original requests.get
    original_get = requests.get

    def fake_get(url,  *args, **kwargs):
        if "/wapi/" in url and "/lease?" in url:            
            response = requests.models.Response()
            response.status_code = 200
                
            # Randomly add next page id for pagination
            if random.randint(1,10) % 2 == 0:
                mock_response["next_page_id"] = "abcdef"
            else:
                mock_response.pop("next_page_id", None)

            # Set the _content as bytes
            response._content = json.dumps(mock_response).encode('utf-8')
            return response            
        return original_get(url,  *args, **kwargs)        

    monkeypatch.setattr(script.requests, "get", fake_get)    
    
    # Load the config file
    with open(SCRIPT_DIR.joinpath("test_config.json")) as config_file:
        cfg = json.load(config_file)

    # Build argv list from key/value pairs
    argv = ["infoblox_script"]
    for key, value in cfg.items():
        argv.append(f"--{key}")
        argv.append(str(value))

    # Patch sys.argv
    monkeypatch.setattr(sys, "argv", argv)

    runpy.run_module("infoblox_script", run_name="__main__")

