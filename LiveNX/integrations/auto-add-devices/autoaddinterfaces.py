import time
import logging
import os
from helper.clickhouse import connect_with_tls
from typing import Dict, Set, Tuple
from multiprocessing import Process
#import requests
import urllib
import ssl
import json
from helper.livenx import get_livenx_inventory, add_interface


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_cickhouse_password():
    """
    <?xml version="1.0" encoding="UTF-8"?>

    <clickhouse>
    <users>
        <default>
        <password replace="true">Fmx.VB.dTr74d</password>
        </default>
    </users>
    </clickhouse>
    """

    try:
        with open('/etc/clickhouse-server/users.d/users.xml', 'r') as f:
            password = f.read()
            # Extract the password using regex
            import re
            match = re.search(r'<password replace="true">(.+?)</password>', password)
            if match:  
                password = match.group(1)
                logging.info("Password extracted from XML file.")
                return password
    except FileNotFoundError:
        pass
    
    password = os.getenv("CLICKHOUSE_PASSWORD", "")
    return None
    
# Retrieve environment variables
liveNxApiHost = os.getenv("LIVENX_API_HOST","")
liveNxApiPort = os.getenv("LIVENX_API_PORT","")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN","")

clickHouseHost = os.getenv("CLICKHOUSE_HOST","localhost")
clickHouseUsername = os.getenv("CLICKHOUSE_USERNAME","default")
clickHousePassword = get_cickhouse_password()
clickHouseApiPort = os.getenv("CLICKHOUSE_PORT","9440")
clickhouseCACerts = os.getenv("CLICKHOUSE_CACERTS", "/path/to/ca.pem")
clickhouseCertfile = os.getenv("CLICKHOUSE_CERTFILE", "clickhouse-server/cacerts/ca.crt")
clickhouseKeyfile = os.getenv("CLICKHOUSE_KEYFILE", "clickhouse-server/cacerts/ca.key")

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

    def get_interface_from_clickhouse(self) -> Dict[str, Set[Tuple[int, int]]]:
        # get all interfaces that aren't marked with dummyseed
        query = """
        SELECT DISTINCT DeviceSerial, IngressIfIndex, EgressIfIndex
        FROM livenx_flowdb.basic_entity_1m_dist
        WHERE time >= now() - INTERVAL 5 MINUTE AND IngressIfName NOT LIKE '%Interface%' AND EgressIfName NOT LIKE '%Interface%'
        """
        
        current_interfaces = {}
        rows = self.client.execute(query)
        
        for device_serial, ingress, egress in rows:
            if device_serial not in current_interfaces:
                current_interfaces[device_serial] = set()
            current_interfaces[device_serial].add((ingress, egress))
            
        return current_interfaces
    
    def update_interfaces(self, livenx_inventory: Dict[str, Set[Tuple[int, str]]], current_interfaces: Dict[str, Set[Tuple[int, int]]]):
        # Add the interfaces to the LiveNX inventory if the ifIndex is not already present
        for device in livenx_inventory.get('devices', []):
            device_serial = device.get('deviceSerial')
            if not device_serial:
                continue
            
            interfaces = device.get('interfaces', [])
            if not interfaces:
                continue
            
            # Check if the device serial is in the current interfaces
            if device_serial not in current_interfaces:
                current_interfaces[device_serial] = set()
            for interface in interfaces:
                if_index = interface.get('ifIndex')
                if not if_index:
                    continue
                
                # Check if the interface is already present in the current interfaces
                if (if_index, 0) not in current_interfaces[device_serial]:
                    # Add the interface to the LiveNX inventory
                    ip4 = interface.get('address')
                    add_interface(device_serial, if_index, ip4)
                    logging.info(f"Added interface {if_index} for device {device_serial}")
                    
                    # Update the current interfaces to include the new interface
                    current_interfaces[device_serial].add((if_index, 0))
                    
    def run(self):
        while True:
            try:
                livenx_inventory = get_livenx_inventory()
                current_interfaces = self.get_interface_from_clickhouse()
                self.update_interfaces(livenx_inventory, current_interfaces)
                time.sleep(300)  # Wait 5 minutes
                
            except Exception as e:
                logging.error(f"Error during monitoring: {e}")
                time.sleep(60)  # Wait 1 minute before retrying on error
    

def start_monitor():
    monitor = InterfaceMonitor()
    monitor.run()

def start_interface_monitor():
    try:
        process = Process(target=start_monitor, args=())
        process.daemon = True  # Set the process as a daemon
        process.start()
        logging.info("Interface monitor started successfully.")
        return process
    except Exception as e:
        logging.error(f"Failed to start interface monitor: {e}")
        raise
