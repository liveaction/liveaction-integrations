import os
import hashlib
import openai
import difflib
import requests
import sqlite3
import csv
import argparse
from datetime import datetime
from netmiko import ConnectHandler

# Configuration for database
DB_FILE = "netflow_audit.db"
GITHUB_REPO_URL = "https://raw.githubusercontent.com/liveaction/liveaction-integrations/configs/"

# Database setup
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY,
        device_host TEXT,
        fetch_time TIMESTAMP,
        config_hash TEXT
    )
    """)
    conn.commit()
    conn.close()

# Read device list from CSV
def read_device_list(device_csv):
    devices = []
    with open(device_csv, "r") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            devices.append({
                "host": row["host"],
                "username": row["username"],
                "password": row["password"],
                "device_type": row["device_type"]
            })
    return devices

# Fetch running configuration
def fetch_running_config(device):
    connection = ConnectHandler(**device)
    running_config = connection.send_command("show running-config")
    connection.disconnect()
    return running_config

# Save configuration if changed
def save_config_if_changed(device_host, running_config):
    config_hash = hashlib.sha256(running_config.encode()).hexdigest()
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT config_hash FROM audit_log WHERE device_host = ? ORDER BY fetch_time DESC LIMIT 1", (device_host,))
    result = cursor.fetchone()

    if not result or result[0] != config_hash:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"configs/{device_host}_{timestamp}.cfg"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w") as file:
            file.write(running_config)

        cursor.execute("INSERT INTO audit_log (device_host, fetch_time, config_hash) VALUES (?, ?, ?)", (device_host, datetime.now(), config_hash))
        conn.commit()

    conn.close()

# Determine model/IOS version
def get_device_info(device):
    connection = ConnectHandler(**device)
    show_version = connection.send_command("show version")
    connection.disconnect()
    
    model = "Unknown"
    ios_version = "Unknown"
    for line in show_version.splitlines():
        if "Model number" in line or "Hardware" in line:
            model = line.split(":")[-1].strip()
        elif "IOS Software" in line or "Version" in line:
            ios_version = line.split(",")[0].split()[-1].strip()
    return model, ios_version

# Pull Golden Config from GitHub
def fetch_golden_config(model, ios_version):
    url = f"{GITHUB_REPO_URL}{model}/{ios_version}.cfg"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Golden config for {model}/{ios_version} not found in repo.")
        return None

# Compare configs
def compare_configs(running_config, golden_config):
    diff = difflib.unified_diff(
        running_config.splitlines(),
        golden_config.splitlines(),
        fromfile="Running Config",
        tofile="Golden Config",
        lineterm=""
    )
    return "\n".join(diff)

# Compare configs using ChatGPT
def compare_configs_chatgpt(running_config, golden_config):
    openai.api_key = os.getenv("OPENAI_API_KEY")

    prompt = (
        "Compare the following running configuration and golden configuration to see if there are any differences:\n"
        "Running Configuration:\n"
        f"{running_config}\n\n"
        "Golden Configuration:\n"
        f"{golden_config}\n\n"
        "Highlight any differences and potential issues."
    )

    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=500,
        temperature=0
    )

    return response.choices[0].text.strip()

# Main workflow
def main(args):
    setup_database()
    devices = read_device_list(args.devicefile)
    
    for device in devices:
        print(f"Processing device: {device['host']}")
        running_config = fetch_running_config(device)
        save_config_if_changed(device['host'], running_config)
        
        model, ios_version = get_device_info(device)
        golden_config = fetch_golden_config(model, ios_version)

        if golden_config:
            diff = compare_configs(running_config, golden_config)
            if diff:
                print(f"Differences found for device {device['host']}:")
                print(diff)
            else:
                print(f"No differences found for device {device['host']}.")

            if args.chatgpt:
                diff = compare_configs_chatgpt(running_config, golden_config)
                if diff:
                    print(f"Differences found for device {device['host']}:")
                    print(diff)
                else:
                    print(f"No differences found for device {device['host']}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit config files.")
    parser.add_argument("--devicefile",  type=str, required=True, default='', help='The device list to read in CSV')
    parser.add_argument("--chatgpt", action="store_false", help="Ask ChatGPT to resolve differences between configs")
    args = parser.parse_args()
    main(args)