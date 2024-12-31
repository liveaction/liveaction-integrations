import time
import logging
import os
from helper.clickhouse import connect_with_tls
from typing import Dict, Set, Tuple
from multiprocessing import Process
import requests
import daemon
import urllib
import ssl
import json

# Retrieve environment variables
liveNxApiHost = os.getenv("LIVENX_API_HOST","")
liveNxApiPort = os.getenv("LIVENX_API_PORT","")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN","")

clickHouseHost = os.getenv("CLICKHOUSE_HOST","localhost")
clickHouseUsername = os.getenv("CLICKHOUSE_USERNAME","default")
clickHousePassword = os.getenv("CLICKHOUSE_PASSWORD","default")
clickHouseApiPort = os.getenv("CLICKHOUSE_PORT","9000")
clickhouseCACerts = os.getenv("CLICKHOUSE_CACERTS", "/path/to/ca.pem")
clickhouseCertfile = os.getenv("CLICKHOUSE_CERTFILE", "clickhouse-server/cacerts/ca.crt")
clickhouseKeyfile = os.getenv("CLICKHOUSE_KEYFILE", "clickhouse-server/cacerts/ca.key")


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigLoader:
    def __init__(self, config_dir="config"):
        self.config_dir = config_dir
        self.interface_defaults = self._load_json("interface_defaults.json")
    
    def _load_json(self, filename):
        try:
            with open(os.path.join(self.config_dir, filename), 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading {filename}: {str(e)}")
            return {}

config_loader = ConfigLoader()

def create_request(url, data = None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "Authorization": "Bearer " + liveNxApiToken
    }
    api_url = "https://" + liveNxApiHost + ":" + liveNxApiPort + url

    request = urllib.request.Request(api_url, headers=headers, data = data)
    return request, ctx

class InterfaceMonitor:
    def __init__(self, connection_params: Dict=None):
        if not(os.path.isfile(clickhouseCertfile) and os.path.isfile(clickhouseKeyfile)):
            logging.error(f"Missing env clickhouse certificate file: {clickhouseCertfile} or key F=file: {clickhouseKeyfile}")
            exit(1)
        self.client = connect_with_tls(host=clickHouseHost, port=clickHouseApiPort, user=clickHouseUsername, password=clickHousePassword, database='livenx_flowdb', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)
        self.previous_interfaces: Dict[str, Set[Tuple[int, int]]] = {}

    def add_interface(self, device_serial: str, if_index: int, ip4: str):
        interface = config_loader.interface_defaults.copy()
        interface.update({
            "ifIndex": if_index,
            "name": f"dummyseed_eth{if_index}/0",
            "address": ip4,
            "wan": False,
            "xcon": False,
            "label": "",
            "stringTags": ""
        })
        payload = {
            "devices": [
                {
                "deviceSerial": f"{device_serial}",
                "interfaces": [{interface}]
                }
            ]
        }
        
        try:
            # Create the request and add the Content-Type header
            request, ctx = create_request(f"/v1/devices/virtual/interfaces", payload)
            logging.info(payload)
            request.add_header("Content-Type", "application/json")
            request.add_header("accept", "application/json")
            # Specify the request method as POST
            request.method = "POST"
            
            with urllib.request.urlopen(request, context=ctx) as response:
                response_data = response.read().decode('utf-8')
                logging.info(response_data)
        except Exception as err:
            logging.error(f"Error on /v1/devices/virtual/interface API Call {err}")
        
        url = self.add_interfaces_url.format(device_serial)
        try:
            response = requests.post(url, json=payload, verify=False)
            response.raise_for_status()
            logging.info(f"API notification successful for device {device_serial}, ifIndex {if_index}")
        except requests.exceptions.RequestException as e:
            logging.error(f"API notification failed: {e}")

    def get_interfaces(self) -> Dict[str, Set[Tuple[int, int]]]:
        # get all interfaces that aren't marked with dummyseed
        query = """
        SELECT DISTINCT DeviceSerial, IngressIfIndex, EgressIfIndex
        FROM livenx_flowdb.basic_entity_1m
        WHERE time >= now() - INTERVAL 5 MINUTE AND IngressIfName NOT LIKE '%dummyseed_eth%' AND EgressIfName NOT LIKE '%dummyseed_eth%'
        """
        
        current_interfaces = {}
        rows = self.client.execute(query)
        
        for device_serial, ingress, egress in rows:
            if device_serial not in current_interfaces:
                current_interfaces[device_serial] = set()
            current_interfaces[device_serial].add((ingress, egress))
            
        return current_interfaces
    
    def compare_interfaces(self, current: Dict[str, Set[Tuple[int, int]]]):
        for device, interfaces in current.items():
            if device in self.previous_interfaces:
                new_interfaces = interfaces - self.previous_interfaces[device]
                if new_interfaces:
                    logging.info(f"New interfaces for {device}: {new_interfaces}")
                    for ingress, egress in new_interfaces:
                        self.add_interface(device, ingress, "")
                        self.add_interface(device, egress, "")
            else:
                logging.info(f"New device detected: {device} with interfaces: {interfaces}")
                for ingress, egress in new_interfaces:
                    self.add_interface(device, ingress, "")
                    self.add_interface(device, egress, "")
    
    def run(self):
        while True:
            try:
                current_interfaces = self.get_interfaces()
                if self.previous_interfaces:
                    self.compare_interfaces(current_interfaces)
                self.previous_interfaces = current_interfaces
                time.sleep(300)  # Wait 5 minutes
                
            except Exception as e:
                logging.error(f"Error during monitoring: {e}")
                time.sleep(60)  # Wait 1 minute before retrying on error
    

def start_monitor():
    # with daemon.DaemonContext():
    monitor = InterfaceMonitor()
    monitor.run()

def start_interface_monitor():
    process = Process(target=start_monitor, args=())
    process.start()
    return process