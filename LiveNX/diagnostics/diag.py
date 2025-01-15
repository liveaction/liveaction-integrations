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

# Function to run tracepath
def version_ip(hostname, port, token, fw):
    if not(hostname and  port and token):
        raise Exception("Missing LiveNx hostname or token")
    headers = {
        "Authorization": "Bearer " + token
    }
    try:
        url = f"https://{hostname}:{port}/v1/version"
        fw.write("Version requested...\n")
        response = requests.get(url, headers=headers, verify=False)
        responses = []
        if response.status_code == 200:
            response_json = response.json()
            responses.append(response_json)
            fw.write(f"API Version: {response_json.get('version')}\n")
        else:
            fw.write(f"Failed to fetch version information: {response.status_code}\n")
        fw.write(f"{'-' * 40}\n")
        return True
    except Exception as err:
        fw.write(f"Error to fetch version: {err}\n")
        fw.write(f"{'-' * 40}\n")
        return False



def fetch_nodes(hostname, port, token, fw):
    if not(hostname and  port and token):
        raise Exception("Missing LiveNx hostname or token")
    
    headers = {
        "Authorization": "Bearer " + token
    }
    try:
        url = f"https://{hostname}:{port}/v1/nodes"
        
        response = requests.get(url, headers=headers, verify=False)
        node_name_mapping = {}
        fw.write("Nodes requested...\n")
        if response.status_code == 200:
            response_json = response.json()
            nodes = response_json.get("nodes", [])

            # Calculate total nodes and sub counts by state
            total_nodes = len(nodes)
            state_counts = {}
            for node in nodes:
                node_id = node.get("id")
                node_name = node.get("name")
                if node_id and node_name:
                    node_name_mapping[node_id] = node_name

                state = node.get("state", "Unknown")
                state_counts[state] = state_counts.get(state, 0) + 1

            # Calculate the percentage of connected nodes
            connected_count = state_counts.get("Connected", 0)
            connected_percentage = (connected_count / total_nodes * 100) if total_nodes > 0 else 0
        
            fw.write(f"Total Nodes: {total_nodes}\n")
            for state, count in state_counts.items():
                fw.write(f"Total '{state}': {count} nodes\n")
            fw.write(f"Percentage of Connected Nodes: {connected_percentage:.2f}%\n")
        else:
            fw.write(f"Failed to fetch nodes: {response.status_code}\n")
        fw.write(f"{'-' * 40}\n")
        return node_name_mapping
    except Exception as err:
        fw.write(f"Error to fetch nodes: {err}\n")
        fw.write(f"{'-' * 40}\n")
        return ""

# Function to fetch system statistics and calculate averages
def fetch_system_statistics(hostname, port, token, fw):
    if not(hostname and  port and token):
        raise Exception("Missing LiveNx hostname or token")
    headers = {
        "Authorization": "Bearer " + token
    }
    try:
        url = f"https://{hostname}:{port}/v1/system/statistics"
        response = requests.get(url, headers=headers, verify=False)
        fw.write("System Statistic requested...\n")
        node_name_mapping = fetch_nodes(hostname, port, token, fw)
        if response.status_code == 200:
            response_json = response.json()
            node_statistics = response_json.get("nodeStatistics", [])

            for node_stat in node_statistics:
                node_id = node_stat.get("nodeId")
                node_name = node_name_mapping.get(node_id, "Unknown Node")
                statistics = node_stat.get("statistics", {})

                os_cpu_total = 0
                jvm_cpu_total = 0
                flow_rate_total = 0
                total_records = len(statistics)

                most_recent_timestamp = max(statistics.keys(), key=lambda x: x) if statistics else None
                total_devices = active_devices = down_devices = None

                for timestamp, data in statistics.items():
                    if data:
                        os_cpu_total += data.get("osCpuUsage", 0)
                        jvm_cpu_total += data.get("jvmCpuUsage", 0)
                        flow_rate_total += data.get("lastFlowRate", 0)

                        # Capture most recent devices info
                        if timestamp == most_recent_timestamp:
                            total_devices = data.get("totalDevices")
                            active_devices = data.get("activeDevices")
                            down_devices = data.get("downDevices")

                # Calculate averages
                avg_os_cpu = os_cpu_total / total_records if total_records > 0 else 0
                avg_jvm_cpu = jvm_cpu_total / total_records if total_records > 0 else 0
                avg_flow_rate = flow_rate_total / total_records if total_records > 0 else 0
                
                fw.write(f"Node Name: {node_name}\n")
                fw.write(f"Average OS CPU Usage: {avg_os_cpu:.2f}%\n")
                fw.write(f"Average JVM CPU Usage: {avg_jvm_cpu:.2f}%\n")
                fw.write(f"Average Flow Rate in FPS: {avg_flow_rate:.2f}%\n")
                if most_recent_timestamp:                
                    fw.write(f"Total Devices: {total_devices}\n")
                    fw.write(f"Active Devices: {active_devices}\n")
                    fw.write(f"Down Devices: {down_devices}\n")
                fw.write(f"{'-' * 20}\n")
        else:
            fw.write(f"Failed to fetch system statistics: {response.status_code}\n")
        fw.write(f"{'-' * 40}\n")
        return True
    except Exception as err:
        fw.write(f"Error to fetch system statistics: {err}\n")
        fw.write(f"{'-' * 40}\n")
        return False

# Function to fetch app mailer settings and display information
def fetch_app_mailer_settings(hostname, port, token, fw):
    if not(hostname and  port and token):
        raise Exception("Missing LiveNx hostname or token")
    headers = {
        "Authorization": "Bearer " + token
    }
    try:
        url = f"https://{hostname}:{port}/v1/appMailer/settings"
        response = requests.get(url, headers=headers, verify=False)
        fw.write("App Mailer Settings requested...\n")
        if response.status_code == 200:
            response_json = response.json()
            app_mailer_config = response_json.get("appMailerConfig", None)

            if app_mailer_config:
                sender_address = app_mailer_config.get("senderAddress", {})
                smtp_settings = app_mailer_config.get("smtpSettings", {})

                sender_email = sender_address.get("address", "Unknown")
                sender_name = sender_address.get("name", "Unknown")
                smtp_host = smtp_settings.get("hostName", "Unknown")
                smtp_port = smtp_settings.get("port", "Unknown")
                smtp_security = smtp_settings.get("security", "Unknown")

                fw.write(f"EMAIL Configuration:\n")
                fw.write(f"Sender Address: {sender_email} ({sender_name})\n")
                fw.write(f"SMTP Host: {smtp_host}\n")
                fw.write(f"SMTP Port: {smtp_port}\n")
                fw.write(f"SMTP Security: {smtp_security}\n")
            else:
                fw.write(f"No Email Configured\n")
        else:
            fw.write(f"Failed to fetch app mailer settings: {response.status_code}\n")
        fw.write(f"{'-' * 40}\n")
        return True
    except Exception as err:
        fw.write(f"Error to fetch app mailer settings: {err}\n")
        fw.write(f"{'-' * 40}\n")
        return False

# Function to fetch syslog configuration and display information
def fetch_syslog_config(hostname, port, token, fw):
    if not(hostname and  port and token):
        raise Exception("Missing LiveNx hostname or token")
    headers = {
        "Authorization": "Bearer " + token
    }
    try:
        url = f"https://{hostname}:{port}/v1/syslog/config"
        response = requests.get(url, headers=headers, verify=False)
        fw.write("Syslog Config requested...\n")
        if response.status_code == 200:
            response_json = response.json()
            syslog_config = response_json.get("syslogAddress", None)

            if syslog_config:
                engineer_console_enable = response_json.get("engineerConsoleEnable", "Unknown")
                syslog_facility = response_json.get("syslogFacility", "Unknown")
                syslog_protocol = response_json.get("syslogProtocol", "Unknown")
                syslog_port = response_json.get("syslogPort", "Unknown")
                syslog_address = response_json.get("syslogAddress", "Unknown")
                app_name = response_json.get("appName", "Unknown")
                hostname_format = response_json.get("hostNameFormat", "Unknown")
                timestamp_format = response_json.get("timeStampFormat", "Unknown")
                process_id_format = response_json.get("processIdFormat", "Unknown")
                
                fw.write(f"SYSLOG Configuration:\n")
                fw.write(f"Engineer Console Enabled: {engineer_console_enable}\n")
                fw.write(f"Syslog Facility: {syslog_facility}\n")
                fw.write(f"Syslog Protocol: {syslog_protocol}\n")
                fw.write(f"Syslog Port: {syslog_port}\n")
                fw.write(f"Syslog IP Address: {syslog_address}\n")
                fw.write(f"App Name: {app_name}\n")
                fw.write(f"Hostname Format: {hostname_format}\n")
                fw.write(f"Timestamp Format: {timestamp_format}\n")
                fw.write(f"Process ID Format: {process_id_format}\n")
            else:
                fw.write(f"SYSLOG is not configured\n")
        else:
            print(f"Failed to fetch syslog configuration: {response.status_code}")
            fw.write(f"Failed to fetch syslog configuration: {response.status_code}\n")
        fw.write(f"{'-' * 40}\n")
        return True
    except Exception as err:
        fw.write(f"Error to fetch syslog configuration: {err}\n")
        fw.write(f"{'-' * 40}\n")
        return False


# Function to fetch SNMP trap configuration and display information
def fetch_snmp_trap_config(hostname, port, token, fw):
    if not(hostname and  port and token):
        raise Exception("Missing LiveNx hostname or token")
    headers = {
        "Authorization": "Bearer " + token
    }
    try:
        url = f"https://{hostname}:{port}/v1/alerting/couriers"
        response = requests.get(url, headers=headers, verify=False)
        fw.write("SNMP Trap Config requested...\n")
        if response.status_code == 200:
            response_json = response.json()
            couriers = response_json.get("couriers", [])
            snmp_trap_configured = False
            for courier in couriers:
                if courier.get("type") == "SNMP_TRAP":
                    snmp_trap_configured = True
                    config = courier.get("config", {})
                    recipients = config.get("recipients", [])

                    if recipients:
                        fw.write(f"SNMP Trap Configuration:\n")
                        for recipient in recipients:
                            address = recipient.get("address", "Unknown")
                            snmp_settings = recipient.get("snmpSettings", {})
                            snmp_version = snmp_settings.get("snmpVersion", "Unknown")
                            port = snmp_settings.get("port", "Unknown")
                            community = snmp_settings.get("settings", {}).get("snmpCommunity", "Unknown")

                            fw.write(f"Destination IP Address: {address}\n")
                            fw.write(f"SNMP Version: {snmp_version}\n")
                            fw.write(f"Port: {port}\n")
                            fw.write(f"Community: {community}\n")
                            fw.write(f"{'-' * 20}\n")
                    else:
                        fw.write(f"SNMP Traps not configured (no recipients)\n")
                        fw.write(f"{'-' * 20}\n")
                    break

            if not snmp_trap_configured:
                fw.write(f"SNMP Traps not configured\n")            
        else:
            print(f"Failed to fetch SNMP Trap configuration: {response.status_code}")
            fw.write(f"Failed to fetch SNMP Trap configuration: {response.status_code}\n")
        fw.write(f"{'-' * 40}\n")
        return True
    except Exception as err:
        fw.write(f"Error to fetch SNMP Trap configuration: {err}\n")
        fw.write(f"{'-' * 40}\n")
        return False


# Function to fetch webhook configuration and display information
def fetch_webhooks_config(hostname, port, token, fw):
    if not(hostname and  port and token):
        raise Exception("Missing LiveNx hostname or token")
    headers = {
        "Authorization": "Bearer " + token
    }
    try:
        url = f"https://{hostname}:{port}/v1/webhooks/"
        response = requests.get(url, headers=headers, verify=False)
        fw.write("Webhooks Config requested...\n")
        if response.status_code == 200:
            response_json = response.json()
            webhooks = response_json if isinstance(response_json, list) else []

            if webhooks:
                fw.write(f"Webhooks Configuration:\n")
                for webhook in webhooks:
                    webhook_id = webhook.get("webhookId", "Unknown")
                    topics = ", ".join(webhook.get("topics", []))
                    username = webhook.get("username", "Unknown")
                    callback_url = webhook.get("callbackUrl", "Unknown")
                    has_auth_header = webhook.get("hasAuthorizationHeader", False)
                    subscription_time = webhook.get("subscriptionTimeMillis", "Unknown")
                    
                    fw.write(f"Webhook ID: {webhook_id}\n")
                    fw.write(f"Subscribed Topics: {topics}\n")
                    fw.write(f"Username: {username}\n")
                    fw.write(f"Callback URL: {callback_url}\n")
                    fw.write(f"Has Authorization Header: {has_auth_header}\n")
                    fw.write(f"Subscription Time: {subscription_time}\n")
                    fw.write(f"{'-' * 20}\n")
            else:
                fw.write(f"No Webhooks Configured\n")
        else:
            fw.write(f"Failed to fetch webhooks configuration: {response.status_code}\n")
        fw.write(f"{'-' * 40}\n")
        return True
    except Exception as err:
        fw.write(f"Error to fetch webhooks configuration: {err}\n")
        fw.write(f"{'-' * 40}\n")
        return False

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

    ###
    parser.add_argument('--livenx_healthcheck', action='store_true', help='Specifies to get health check')
    parser.add_argument('--livenx_ip', required=False, help='Specifies liveNX host')
    parser.add_argument('--livenx_port', required=False, default='8093', help='liveNx port for API interaction')
    parser.add_argument('--livenx_token', required=False, default='', help='liveNx token for API interaction')
    
    

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
    
    if args.livenx_healthcheck == True:
        log_file = f'health_check_{datetime.now().strftime("%Y%m%d%H%M%S")}.log'
        with open(log_file, 'w') as fw:
            version_ip(args.livenx_ip,args.livenx_port,args.livenx_token, fw)
            node_name_mapping = fetch_nodes(args.livenx_ip,args.livenx_port,args.livenx_token, fw)
            fetch_system_statistics(args.livenx_ip,args.livenx_port,args.livenx_token, fw)
            fetch_app_mailer_settings(args.livenx_ip,args.livenx_port,args.livenx_token, fw)
            fetch_syslog_config(args.livenx_ip,args.livenx_port,args.livenx_token, fw)

                # Fetch SNMP trap configuration and print report
            fetch_snmp_trap_config(args.livenx_ip,args.livenx_port,args.livenx_token, fw)

            # Fetch webhooks configuration and print report
            fetch_webhooks_config(args.livenx_ip,args.livenx_port,args.livenx_token, fw)
