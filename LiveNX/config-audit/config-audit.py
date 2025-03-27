import os
import hashlib
import openai
import difflib
import requests

import csv
import argparse
import boto3
import json
from datetime import datetime
import sqlite3
import urllib.parse
from datetime import datetime
from netmiko import ConnectHandler

clickHouseHost = os.getenv("CLICKHOUSE_HOST","localhost")
clickHouseUsername = os.getenv("CLICKHOUSE_USERNAME","default")
clickHousePassword = os.getenv("CLICKHOUSE_PASSWORD","default")
clickHouseApiPort = os.getenv("CLICKHOUSE_PORT","9000")
clickhouseCACerts = os.getenv("CLICKHOUSE_CACERTS", "/path/to/ca.pem")
clickhouseCertfile = os.getenv("CLICKHOUSE_CERTFILE", "/etc/clickhouse-server/cacerts/ca.crt")
clickhouseKeyfile = os.getenv("CLICKHOUSE_KEYFILE", "/etc/clickhouse-server/cacerts/ca.key")


GITHUB_REPO_URL = "https://raw.githubusercontent.com/liveaction/liveaction-integrations/refs/heads/main/LiveNX/configs/"
    
def create_netmiko_list(original_devices):
    device_list_copy = [
        {key.lower(): value for key, value in device.items() if key in {"Device_Type", "Host", "Username", "Password"}}
        for device in original_devices
    ]
    return device_list_copy

# Read device list from CSV
def read_device_list(device_csv):
    devices = []
    try:
        with open(device_csv, "r") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Skip rows where "ADD/UPDATE" is not "true"
                if row["ADD/UPDATE"].strip().lower() != "true" or row["TYPE"].strip().lower() == "interface" or row["TYPE"].strip().lower() == "group":
                    continue

                device_type = row.get("VENDOR", "").strip().lower()

                if device_type == "cisco":
                    device_type = "cisco_ios"
                elif device_type == "arista":
                    device_type = "arista_eos"
                elif device_type == "juniper":
                    device_type = "juniper_junos"
                else:
                    if row.get("MODEL", "").strip().lower() == "ex":
                        device_type = "juniper"
                    else:
                        device_type = "cisco_ios"                       

                # Append the device with selected fields
                devices.append({
                    "Name": row.get("NAME", "").strip(),
                    "Device_Type": device_type,
                    "Device_Serial": row.get("DEVICE SERIAL", "").strip(),
                    "Host": row.get("IP ADDRESS", "").strip(),
                    "Vendor": row.get("VENDOR", "").strip(),
                    "Model": row.get("MODEL", "").strip(),
                    "Ios_Version": row.get("IOS VERSION", "").strip(),
                    "Description": row.get("DESCRIPTION", "").strip(),
                    "Wan": row.get("WAN", "").strip(),
                    "Service_Provider": row.get("SERVICE PROVIDER", "").strip(),
                    "Site": row.get("SITE", "").strip(),
                    "Site_Cidr": row.get("SITE CIDR", "").strip(),
                    "Poll": row.get("POLL", "").strip().lower() == "true",
                    "Poll_Qos": row.get("POLL QOS", "").strip().lower() == "true",
                    "Poll_Flow": row.get("POLL FLOW", "").strip().lower() == "true",
                    "Poll_Ip_Sla": row.get("POLL IP SLA", "").strip().lower() == "true",
                    "Poll_Routing": row.get("POLL ROUTING", "").strip().lower() == "true",
                    "Poll_Lan": row.get("POLL LAN", "").strip().lower() == "true",
                    "Poll_Interval_Msec": int(row.get("POLL INTERVAL (MSEC)", "0").strip() or 0),
                    "Username": row.get("USERNAME", "admin").strip(),
                    "Password": row.get("PASSWORD", "admin").strip(),
                    "Golden_File": row.get("GOLDEN FILE", "").strip(),
                })


    except FileNotFoundError:
        print(f"Error: The file {device_csv} was not found.")
    except Exception as e:
        print(f"Error: An unexpected error occurred while reading the file {device_csv}: {e}")
    
    return devices

# Fetch running configuration
def fetch_running_config(device):
    try:
        connection = ConnectHandler(**device)
        running_config = connection.send_command("show running-config")
        connection.disconnect()
        return running_config
    except Exception as e:
        print(f"Error fetching running config for device {device['host']}: {e}")
        return None

def save_config_if_changed_sqlite(device, running_config):
    # Hash the running configuration
    config_hash = hashlib.sha256(running_config.encode()).hexdigest()

    # Connect to SQLite database
    conn = sqlite3.connect('inventory_db.sqlite')
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Audit_Log (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT,
            Device_Type TEXT,
            Device_Serial TEXT,
            Host TEXT,
            Vendor TEXT,
            Model TEXT,
            Ios_Version TEXT,
            Description TEXT,
            Wan TEXT,
            Service_Provider TEXT,
            Site TEXT,
            Site_Cidr TEXT,
            Poll BOOLEAN,
            Poll_Qos BOOLEAN,
            Poll_Flow BOOLEAN,
            Poll_Ip_Sla BOOLEAN,
            Poll_Routing BOOLEAN,
            Poll_Lan BOOLEAN,
            Poll_Interval_Msec INTEGER,
            Golden_File TEXT,
            Fetch_Time TEXT,
            Config_Hash TEXT,
            Config_Content TEXT
        )
    """)

    # Check for existing config hash
    query = """
        SELECT Config_Hash 
        FROM Audit_Log 
        WHERE Host = ? 
        ORDER BY Fetch_Time DESC 
        LIMIT 1
    """
    device_host = device['Host']
    try:
        cursor.execute(query, (device_host,))
        result = cursor.fetchone()
    except Exception as e:
        print(f"Error executing query for device {device_host}: {e}")
        conn.close()
        return None

    if not result or result[0] != config_hash:
        # Save to file system as backup if the config is different
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(os.getcwd(), f"{device_host}_{timestamp}.cfg")
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w") as file:
            file.write(running_config)

        # Insert new record with all columns
        insert_query = """
            INSERT INTO Audit_Log (
                Name, Device_Type, Device_Serial, Host, Vendor, Model, Ios_Version, 
                Description, Wan, Service_Provider, Site, Site_Cidr, Poll, Poll_Qos, 
                Poll_Flow, Poll_Ip_Sla, Poll_Routing, Poll_Lan, Poll_Interval_Msec, 
                Golden_File, Fetch_Time, Config_Hash, Config_Content
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """
        insert_data = (
            device.get('Name', ''),
            device.get('Device_Type', ''),
            device.get('Device_Serial', ''),
            device_host,
            device.get('Vendor', ''),
            device.get('Model', ''),
            device.get('Ios_Version', ''),
            device.get('Description', ''),
            device.get('Wan', ''),
            device.get('Service_Provider', ''),
            device.get('Site', ''),
            device.get('Site_Cidr', ''),
            device.get('Poll', False),
            device.get('Poll_Qos', False),
            device.get('Poll_Flow', False),
            device.get('Poll_Ip_Sla', False),
            device.get('Poll_Routing', False),
            device.get('Poll_Lan', False),
            device.get('Poll_Interval_Msec', 0),
            device.get('Golden_File', ''),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            config_hash,
            running_config
        )
        
        # Execute the insert query
        try:
            cursor.execute(insert_query, insert_data)
            conn.commit()
        except Exception as e:
            print(f"Error inserting new config for device {device_host}: {e}")
            conn.close()
            return None

    conn.close()

def get_device_info(device, model = '', ios_version = ''):
    try:
        connection = ConnectHandler(**device)
        show_version = connection.send_command("show version")
        connection.disconnect()
    except Exception as e:
        print(f"Error fetching device info for {device['host']}: {e}")
        return model, ios_version

    for line in show_version.splitlines():
        if ios_version == '' and "Cisco IOS XE Software" in line:
            ios_version = line.split(",")[1].strip()
        elif model == '' and "cisco" in line.lower() and "(revision" in line.lower():
            model = line.split()[1]
    
    return model, ios_version


# Pull Golden Config from GitHub
def fetch_golden_config(output_file, model, ios_version, golden_file):
    # Encode model and ios_version to handle spaces and special characters

    if golden_file != '':
        if os.path.exists(golden_file):
            with open(golden_file, "r") as file:
                return file.read()
        else:
            output_file.write(f"Golden config file {golden_file} not found.")
            return None
    encoded_model = urllib.parse.quote(model)
    encoded_ios_version = urllib.parse.quote(ios_version)
    
    # Construct the URL with encoded components
    url = f"{GITHUB_REPO_URL}{encoded_model}/{encoded_ios_version}.cfg"
    
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        output_file.write(f"Golden config for {model}/{ios_version} not found in repo at URL {url}.")
        return None

import difflib
import re

def compare_configs(running_config, golden_config, skip_regex_file=None):
    # Load the skip regexes from the provided file (one regex per line)
    if skip_regex_file:
        try:
            with open(skip_regex_file, "r") as file:
                skip_regexes = {re.compile(line.strip()) for line in file.readlines() if line.strip()}
        except FileNotFoundError:
            raise FileNotFoundError(f"The skip regex file '{skip_regex_file}' was not found.")
    else:
        skip_regexes = set()

    # Filter lines to exclude those that are empty or match any of the skip_regexes
    def filter_lines(config_lines):
        return [
            line for line in config_lines
            if line.strip() and not any(regex.match(line) for regex in skip_regexes)
        ]

    # Apply filtering to both running_config and golden_config
    running_config_lines = filter_lines(running_config.splitlines())
    golden_config_lines = filter_lines(golden_config.splitlines())

    # Perform the diff comparison
    diff = difflib.unified_diff(
        running_config_lines,
        golden_config_lines,
        fromfile="Running Config",
        tofile="Golden Config",
        lineterm=""
    )

    return "\n".join(diff)

# Main execution logic
def main(args):
    devices = read_device_list(args.devicefile)
    netmiko_device_list = create_netmiko_list(devices)
    skip_regex_file = os.path.join(os.getcwd(), "LiveNX/config-audit/config/skip-regexes.txt")

    for netmiko_device in netmiko_device_list:
        device = devices[netmiko_device_list.index(netmiko_device)]
        # Create subdirectories and file for each device
        device_host = netmiko_device['host']
        output_dir = os.path.join(os.getcwd(), f"LiveNX/config-audit/output/{device_host}")

        # Create the directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Now, open the output file for appending
        output_file_path = os.path.join(output_dir, "diffoutput.txt")
        output_file = open(output_file_path, "w")
        try:
            running_config = fetch_running_config(netmiko_device)
            if running_config is None:
                raise ValueError("Failed to fetch running config")
            
            if args.sqlite:
                save_config_if_changed_sqlite(device, running_config)
          
            model, ios_version = get_device_info(netmiko_device)
            golden_config = fetch_golden_config(output_file, model, ios_version, device['Golden_File'])
            if golden_config is None:
                raise ValueError("Golden config not found")

            diff = compare_configs(running_config, golden_config, skip_regex_file)
            output_file.write(f"Device: {netmiko_device['host']}\n")
            output_file.write(diff + "\n\n")

        except FileNotFoundError as fnf_error:
            handle_error(output_file, netmiko_device['host'], fnf_error)
        except ValueError as val_error:
            handle_error(output_file, netmiko_device['host'], val_error)
        except Exception as e:
            handle_error(output_file, netmiko_device['host'], e)
        finally:
            output_file.close()

def handle_error(output_file, device_host, error):
    error_type = type(error).__name__
    output_file.write(f"Device: {device_host} - {error_type}: {str(error)}\n\n")
    print(f"Error for device {device_host}: {error_type} - {str(error)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit config files.")
    parser.add_argument("--devicefile",  type=str, required=True, default='', help='The device list to read in CSV')
    parser.add_argument("--sqlite", default=False, action="store_true", help="Save configs to sqlite")
    args = parser.parse_args()
    main(args)
