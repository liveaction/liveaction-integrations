import os
import subprocess
import time
import requests
import argparse
import threading
import urllib
import urllib3
from datetime import datetime, timedelta

# Suppress the SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_vmanage_client_token(vmanage_ip, vmanage_port, username, password):
    try:
        base_url = f'https://{vmanage_ip}:{vmanage_port}/dataservice'
        token_url = f'{base_url}/client/token'
        
        # Create a session for authentication
        session = requests.Session()

        # First, log in to get an authenticated session
        login_url = f'{base_url}/j_security_check'
        login_data = {'j_username': username, 'j_password': password}

        # Login to vManage
        login_response = session.post(login_url, data=login_data, verify=False)
        print(login_response)
        if login_response.status_code != 200 or 'JSESSIONID' not in session.cookies:
            print("Failed to login to vManage.")
            return

        # Request token from /client/token
        print(f'Requesting vManage URL {token_url}')
        token_response = session.get(token_url, verify=False)
        if token_response.status_code == 200:
            # Extract the token from the headers
            token = token_response.text
            if token:
                print(f'Token: {token}')
                return token
            else:
                print('Token not found.')
        else:
            print(f"Failed to get token from vManage: {token_response.status_code}")

    except Exception as e:
        print(f"vManage API error: {e}")
    return None

# Function to run SNMP walk on a specific IP
def snmp_v2_walk(ip_address, community='public'):
    try:
        print(f"Running SNMPv2 walk on {ip_address}...")
        result = subprocess.run(['snmpwalk', '-v2c', '-c', community, ip_address], capture_output=True, text=True)
        if result.returncode == 0:
            with open('snmpv2_walk_output.txt', 'w') as f:
                f.write(result.stdout)
            print("SNMPv2 walk completed successfully.")
        else:
            print(f"Error running SNMPv2 walk: {result.stderr}")
    except Exception as e:
        print(f"SNMPv2 walk error: {e}")

# Function to run SNMP walk on a specific IP
def snmp_v3_walk(ip_address, snmpwalkuser='admin', snmpauthpassword='password', snmpwalkpassphrase='passphrase'):
    try:
        print(f"Running SNMPv3 walk on {ip_address}...")
        result = subprocess.run(['snmpwalk', '-v3', '-l', 'authpriv', '-u', snmpwalkuser, '-a', 'SHA', '-x', 'AES', '-A', snmpauthpassword, '-X', snmpwalkpassphrase, ip_address], capture_output=True, text=True)
        if result.returncode == 0:
            with open('snmpv3_walk_output.txt', 'w') as f:
                f.write(result.stdout)
            print("SNMPv3 walk completed successfully.")
        else:
            print(f"Error running SNMP walk: {result.stderr}")
    except Exception as e:
        print(f"SNMPv3 walk error: {e}")

# Function to capture packets on eth0
def capture_packets(interface='eth0', duration=60):
    try:
        print(f"Starting packet capture on {interface} for {duration} seconds...")
        pcap_file = f'packet_capture_{datetime.now().strftime("%Y%m%d%H%M%S")}.pcap'
        capture_command = ['tcpdump', '-i', interface, '-w', pcap_file]
        proc = subprocess.Popen(capture_command)
        time.sleep(duration)
        proc.terminate()
        print(f"Packet capture saved to {pcap_file}.")
    except Exception as e:
        print(f"Packet capture error: {e}")

# Function to get vManage API data for a specific IP
def get_vmanage_data(vmanage_ip, vmanage_port, username, password, token, url_path, url_params = '', vmanage_max_count = 0):
    try:
        scrollId = None
        totalcount = 0
        while True:
            base_url = f"https://{vmanage_ip}:{vmanage_port}/dataservice"
            # Create a session for authentication
            session = requests.Session()

            if token == None:
                session.auth = (username, password)
            else:
                session.headers.update({'X-XSRF-TOKEN': token})

            full_path = f'{base_url}/{url_path}'
            if scrollId != None:
                full_path += "?scrollId=" + urllib.parse.quote(scrollId)
            else:
                full_path += f'{url_params}'
            
            print(f'Requesting vManage URL {full_path}')
            response = session.get(f'{full_path}', verify=False)
            response.raise_for_status()  # Raise an exception for bad status codes

            data = response.json()
            print(f'RESPONSE={data}')

            if response.status_code == 200:
                with open(f'vmanage_data_json', 'a+') as f:
                    f.write(f'***********************{full_path}*************************************\n')
                    f.write(response.text)
                    
                print("vManage data collected successfully.")
            else:
                print(f"Failed to get data from vManage: {response.status_code}")
                break

            if 'pageInfo' not in data:
                break     

            if 'hasMoreData' not in data['pageInfo']:
                break               

            if data['pageInfo']['hasMoreData'] == False:
                break

            scrollId = data['pageInfo']['scrollId']
            count = data['pageInfo']['count']
            totalcount += int(count)

            if totalcount >= vmanage_max_count:
                break

    except Exception as e:
        print(f"vManage API error: {e}")

# Function to collect system logs during the diagnostics
def collect_logs():
    try:
        print("Collecting system logs...")
        log_file = f'system_logs_{datetime.now().strftime("%Y%m%d%H%M%S")}.log'
        with open(log_file, 'w') as f:
            result = subprocess.run(['journalctl', '-n', '1000', '--no-pager'], capture_output=True, text=True)
            f.write(result.stdout)
        print(f"System logs collected in {log_file}.")
    except Exception as e:
        print(f"Error collecting logs: {e}")

# Function to ping an IP address
def ping_ip(ip_address, count=4):
    try:
        print(f"Pinging {ip_address}...")
        result = subprocess.run(['ping', '-c', str(count), ip_address], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"Ping failed: {result.stderr}")
    except Exception as e:
        print(f"Ping error: {e}")

# Function to run tracepath
def tracepath_ip(ip_address):
    try:
        print(f"Running tracepath to {ip_address}...")
        result = subprocess.run(['tracepath', ip_address], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
            with open('tracepath_output.txt', 'w') as f:
                f.write(result.stdout)
        else:
            print(f"tracepath failed: {result.stderr}")
    except Exception as e:
        print(f"tracepath error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run diagnostics on a network device.")
    parser.add_argument('--target_ip', required=False, help='Target IP address for SNMP, ping, and tracepath')
    parser.add_argument('--vmanage_ip', required=False, help='vManage IP address for API interaction')
    parser.add_argument('--vmanage_port', required=False, default='8443', help='vManage port for API interaction')
    parser.add_argument('--vmanage_username', required=False, help='vManage username')
    parser.add_argument('--vmanage_password', required=False, help='vManage password')
    parser.add_argument('--vmanage_mins', required=False, default='10', help='vManage number of minutes to collect data')
    parser.add_argument('--vmanage_max_count', required=False, default='1000', help='vManage maximum number of records to collect')
    parser.add_argument('--capture', action='store_true', help='Specifies if a capture should be run')
    parser.add_argument('--logs', action='store_true', help='Specifies if a logs should be collected')
    parser.add_argument('--ping', action='store_true', help='Specifies if a ping should be collected')
    parser.add_argument('--trace', action='store_true', help='Specifies if a tracepath should be collected')
    parser.add_argument('--snmpv3', action='store_true', help='Specifies if a tracepath should be collected')
    parser.add_argument('--snmpv2walkcommunity', required=False, help='snmpwalk v2 community')
    parser.add_argument('--snmpv3walkuser', required=False, help='snmpwalk v3 username')
    parser.add_argument('--snmpv3authpassword', required=False, help='snmpwalk v3 password')
    parser.add_argument('--snmpv3walkpassphrase', required=False, help='snmlwalk v3 passphrase')
    parser.add_argument('--vmanage_use_token', action='store_true', help='Specifies if vManage token auth should be used')
    

    args = parser.parse_args()

    print(args)

    # Start packet capture in a separate thread

    if args.capture == True:
        capture_thread = threading.Thread(target=capture_packets, kwargs={'interface': 'eth0', 'duration': 60})
        capture_thread.start()
        # wait for 
        time.sleep(2)

    if args.snmpv3walkuser != None:
        # Run SNMP walk
        snmp_v3_walk(args.target_ip, args.snmpv3walkuser, args.snmpv3authpassword, args.snmpv3walkpassphrase)

    if args.snmpv2walkcommunity != None:
        # Run SNMP walk
        snmp_v2_walk(args.target_ip, args.snmpv2walkcommunity)

    if args.vmanage_ip != None:
        # Collect vManage API data
        endtime = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        starttime = (datetime.now() - timedelta(minutes=int(args.vmanage_mins))).strftime("%Y-%m-%dT%H:%M:%S")
        token = None
        
        if args.vmanage_use_token == True:
            token = get_vmanage_client_token(args.vmanage_ip, args.vmanage_port, args.vmanage_username, args.vmanage_password)
        get_vmanage_data(args.vmanage_ip, args.vmanage_port, args.vmanage_username, args.vmanage_password, token, f'device')
        get_vmanage_data(args.vmanage_ip, args.vmanage_port, args.vmanage_username, args.vmanage_password, token, f'data/device/statistics/approutestatsstatistics', f'?endDate={endtime}&startDate={starttime}&timeZone=GMT', int(args.vmanage_max_count))
        get_vmanage_data(args.vmanage_ip, args.vmanage_port, args.vmanage_username, args.vmanage_password, token, f'data/device/statistics/approutestatsstatistics', f'?endDate={endtime}&startDate={starttime}&timeZone=GMT')
        get_vmanage_data(args.vmanage_ip, args.vmanage_port, args.vmanage_username, args.vmanage_password, token, f'data/device/state/ControlWanInterface?count=500')
        get_vmanage_data(args.vmanage_ip, args.vmanage_port, args.vmanage_username, args.vmanage_password, token, f'template/policy/vsmart')
       

    # Ping the target IP address
    if args.ping == True:
        ping_ip(args.target_ip)

    # Run tracepath to the target IP address
    if args.trace == True:
        tracepath_ip(args.target_ip)

    if args.capture == True:
        # Wait for packet capture to complete
        capture_thread.join()

    if args.logs == True:
        # Collect logs
        collect_logs()
