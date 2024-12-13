import os
import hashlib
import openai
import difflib
import requests
import sqlite3
import csv
import argparse
import boto3
import json

import urllib.parse
from datetime import datetime
from netmiko import ConnectHandler

# Configuration for database
DB_FILE = "netflow_audit.db"
GITHUB_REPO_URL = "https://raw.githubusercontent.com/liveaction/liveaction-integrations/refs/heads/main/LiveNX/configs/"

def create_netmiko_list(original_devices):
    device_list_copy = [
        {key: value for key, value in device.items() if key not in {"model", "ios_version"}}
        for device in original_devices
    ]
    return device_list_copy
        
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
                "device_type": row["device_type"],
                "model": row["model"],
                "ios_version": row["ios_version"],
                "golden_file": row["golden_file"]
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
def get_device_info(device, model = '', ios_version = ''):
    connection = ConnectHandler(**device)
    show_version = connection.send_command("show version")
    connection.disconnect()

    for line in show_version.splitlines():
        if ios_version == '' and "Cisco IOS XE Software" in line:
            ios_version = line.split(",")[1].strip()
        elif model == '' and "cisco" in line.lower() and "(revision" in line.lower():
            model = line.split()[1]
    
    return model, ios_version



# Pull Golden Config from GitHub
def fetch_golden_config(model, ios_version, golden_file):
    # Encode model and ios_version to handle spaces and special characters

    if golden_file != '':
        if os.path.exists(golden_file):
            with open(golden_file, "r") as file:
                return file.read()
        else:
            print(f"Golden config file {golden_file} not found.")
            return None
    encoded_model = urllib.parse.quote(model)
    encoded_ios_version = urllib.parse.quote(ios_version)
    
    # Construct the URL with encoded components
    url = f"{GITHUB_REPO_URL}{encoded_model}/{encoded_ios_version}.cfg"
    
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Golden config for {model}/{ios_version} not found in repo at URL {url}.")
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


def compare_configs_claude(running_config, golden_config):
    """
    Compare configurations using Claude 3.5 Sonnet via AWS Bedrock
    
    Args:
        running_config (str): The current running configuration
        golden_config (str): The reference or ideal configuration
    
    Returns:
        str: Comparison analysis from Claude
    """
    # Create a Bedrock Runtime client with credentials from environment
    bedrock_runtime = boto3.client(
        service_name='bedrock-runtime', 
        region_name=os.getenv('AWS_REGION', 'us-east-1'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        # Optional: AWS Session Token if using temporary credentials
        # aws_session_token=os.getenv('AWS_SESSION_TOKEN')
    )
        
    # Construct the prompt for Claude
    prompt = (
        "Compare the following running configuration and golden configuration to see if there are any differences:\n"
        "Running Configuration:\n"
        f"{running_config}\n\n"
        "Golden Configuration:\n"
        f"{golden_config}\n\n"
        "Highlight any differences and potential issues. Also generate a diff that the network user can apply on the running config for the flow monitoring related settings."
    )

    # Prepare the request payload for Claude 3.5 Sonnet
    request_body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 500,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0
    })

    response = ""
    try:
        # Invoke Claude 3.5 Sonnet model
        response = bedrock_runtime.invoke_model(
            modelId="anthropic.claude-3-5-sonnet-20240620-v1:0",
            contentType="application/json",
            body=request_body
        )

        # Parse the response
        response_body = json.loads(response['body'].read())
        
        # Extract and return the text response
        response = response_body['content'][0]['text']

    except Exception as e:
        return f"An error occurred: {str(e)}"
    
    return response


def compare_configs_liveassist(running_config, golden_config):
    # Define the host and port
    host = os.getenv('LIVEASSIST_HOST')
    port = os.getenv('LIVEASSIST_PORT', '443')
    username = os.getenv('LIVEASSIST_USERNAME')
    password = os.getenv('LIVEASSIST_PASSWORD')

    # Login endpoint
    login_url = f"https://{host}:{port}/api/v1/login"
    login_payload = {
        "username": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json",
        "Host" : host,
        "Accept" : "*/*",
        "Connection" : "keep-alive",
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
    }

    # Log in to obtain tokens
    response = requests.post(login_url, json=login_payload, headers=headers, verify=False)
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens.get("AccessToken")
        refresh_token = tokens.get("RefreshToken")
        id_token = tokens.get("IdToken")
        print("Login successful. Tokens received.")
    else:
        print(f"Login failed. Status code: {response.status_code}, Response: {response.text}")
        exit(1)

    # Use AccessToken to call the AI chain endpoint
    chain_url = f"https://{host}:{port}/api/v1/ai/chain"
    auth_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Host" : host,
        "Accept" : "*/*",
        "Connection" : "keep-alive",
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
    }

    message_payload = {
        "name": "Test token",
        "table_names": "structured_events",
        "db": "flows",
        "response_format": "json"
    }

    chain_response = requests.post(chain_url, json=message_payload, headers=auth_headers, verify=False)
    if chain_response.status_code == 200:
        chain_data = chain_response.json()
        chain_id = chain_data.get("chain_id")
        print(f"Chain ID: {chain_id}")
    else:
        print(f"Failed to fetch chain data. Status code: {chain_response.status_code}, Response: {chain_response.text}")

        # Call the chain message endpoint
    message_url = f"https://{host}:{port}/api/v1/ai/chain/{chain_id}/message"
    message_payload = {
        "query": f"Compare the following running configuration and golden configuration to see if there are any differences:\nRunning Configuration:\n{running_config}\nGolden Configuration:\n{golden_config}\nHighlight any differences and potential issues."
    }

    message_response = requests.post(message_url, json=message_payload, headers=auth_headers, verify=False)
    if message_response.status_code == 200:
        message_data = message_response.json()
        query = message_data.get("query")
        response_description = message_data.get("response", {}).get("description")
        values = message_data.get("response", {}).get("values", [])

        print(f"Query: {query}")
        print(f"Response Description: {response_description}")
        print(f"Values: {values}")
    else:
        print(f"Failed to fetch message data. Status code: {message_response.status_code}, Response: {message_response.text}")



# Main workflow
def main(args):
    setup_database()
    devices = read_device_list(args.devicefile)
    netmiko_devices = create_netmiko_list(devices)
    
    i = 0
    for netmiko_device in netmiko_devices:
        device = devices[i]
        i = i + 1
        print(f"Processing device: {netmiko_device['host']}")
        running_config = fetch_running_config(netmiko_device)
        save_config_if_changed(netmiko_device['host'], running_config)
        
        model, ios_version = get_device_info(netmiko_device, device['model'], device['ios_version'])
        golden_config = fetch_golden_config(model, ios_version, device['golden_file'])

        if golden_config:
            diff = compare_configs(running_config, golden_config)
            if diff:
                print(f"Differences found for device {netmiko_device['host']}:")
                print(diff)
            else:
                print(f"No differences found for device {netmiko_device['host']}.")

            if args.chatgpt:
                diff = compare_configs_chatgpt(running_config, golden_config)
                if diff:
                    print(f"Differences found for device {netmiko_device['host']}:")
                    print(diff)
                else:
                    print(f"No differences found for device {netmiko_device['host']}.")

            if args.bedrock:
                diff = compare_configs_claude(running_config, golden_config)
                if diff:
                    print(f"Differences found for device {netmiko_device['host']}:")
                    print(diff)
                else:
                    print(f"No differences found for device {netmiko_device['host']}.")

            if args.liveassist:
                diff = compare_configs_liveassist(running_config, golden_config)
                if diff:
                    print(f"Differences found for device {netmiko_device['host']}:")
                    print(diff)
                else:
                    print(f"No differences found for device {netmiko_device['host']}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit config files.")
    parser.add_argument("--devicefile",  type=str, required=True, default='', help='The device list to read in CSV')
    parser.add_argument("--bedrock", default=False, action="store_true", help="Ask Amazon Bedrock to resolve differences between configs")
    parser.add_argument("--chatgpt", default=False, action="store_true", help="Ask ChatGPT to resolve differences between configs")
    parser.add_argument("--liveassist", default=False, action="store_true", help="Ask LiveAssist to resolve differences between configs")
    args = parser.parse_args()
    main(args)