import time
import logging
import os
from helper.clickhouse import connect_with_tls
from typing import Dict, Set, Tuple
from multiprocessing import Process
import argparse
import urllib
import ssl
import json
import sys
from helper.livenx import get_livenx_inventory, set_interfaces

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
local_logger = logging.getLogger(__name__)


def get_clickhouse_password():
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
clickHousePassword = get_clickhouse_password()
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
            local_logger.error(f"Error loading {filename}: {str(e)}")
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
            local_logger.error(f"Missing env clickhouse certificate file: {clickhouseCertfile} or key F=file: {clickhouseKeyfile}")
            exit(1)
        self.client = connect_with_tls(host=clickHouseHost, port=clickHouseApiPort, user=clickHouseUsername, password=clickHousePassword, database='livenx_flowdb', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)
        self.previous_interfaces: Dict[str, Set[Tuple[int, int]]] = {}

    def get_interface_from_clickhouse(self) -> Dict[str, Set[Tuple[int, int]]]:
        # get all interfaces that aren't marked with dummyseed
        query = """
        SELECT DISTINCT DeviceSerial, IngressIfIndex, EgressIfIndex
        FROM livenx_flowdb.basic_entity_5m_dist
        WHERE time >= now() - INTERVAL 15 MINUTE AND IngressIfName NOT LIKE '%Interface%' AND EgressIfName NOT LIKE '%Interface%'
        """
        
        current_interfaces = {}
        rows = self.client.execute(query)
        
        for device_serial, ingress, egress in rows:
            if device_serial not in current_interfaces:
                current_interfaces[device_serial] = set()
            current_interfaces[device_serial].add((ingress, egress))
           
        return current_interfaces
    
    def update_interfaces(self, livenx_inventory, current_interfaces: Dict[str, Set[Tuple[int, int]]]):
        # Add the interfaces to the LiveNX inventory if the ifIndex is not already present from the current_interfaces
        for device in livenx_inventory.get('devices', []):
            device_serial = device.get('serial')
            if not device_serial:
                continue
            
            interfaces = device.get('interfaces', [])
            if len(interfaces) == 0:
                continue
            ip4 = interfaces[0].get('address')
            # Check if the device serial is in the current interfaces
            existing_interfaces = []
            for interface in interfaces:
                existing_interfaces.append(interface.get('ifIndex'))
            local_logger.debug(f"EXISTING={existing_interfaces}")
            final_interfaces = existing_interfaces.copy()
            current_device_interfaces = current_interfaces.get(device_serial, set())
            for current_interface in current_device_interfaces:
                if current_interface[0] not in final_interfaces:
                    # Check if the interface is already added
                    # Add the interface to the LiveNX inventory
                    local_logger.info(f"Added interface {current_interface[0]} to device {device_serial} with ip {ip4}")
                    final_interfaces.append(current_interface[0])
                if current_interface[1] not in final_interfaces:
                    # Check if the interface is already added
                    # Add the interface to the LiveNX inventory
                    local_logger.info(f"Added interface {current_interface[1]} to device {device_serial} with ip {ip4}")
                    final_interfaces.append(current_interface[1])

            # only add a new set of interfaces if the list of interfaces change
            if len(final_interfaces) != len(existing_interfaces):
                local_logger.debug(f"FINAL={final_interfaces}")
                set_interfaces(device_serial, final_interfaces, ip4)

    def run_one_cycle(self):
        try:
            livenx_inventory = get_livenx_inventory()
            current_interfaces = self.get_interface_from_clickhouse()
            self.update_interfaces(livenx_inventory, current_interfaces)
        except Exception as e:
            local_logger.error(f"Error during monitoring: {e}")

    def run(self):
        while True:
            try:
                self.run_one_cycle()
                time.sleep(900)  # Wait 1 minute before the next cycle                
            except Exception as e:
                local_logger.error(f"Error during monitoring: {e}")
                time.sleep(60)  # Wait 1 minute before retrying on error
    

def start_monitor():
    monitor = InterfaceMonitor()
    monitor.run()

def start_interface_monitor():
    try:
        process = Process(target=start_monitor, args=())
        process.daemon = True  # Set the process as a daemon
        process.start()
        local_logger.info("Interface monitor started successfully.")
        return process
    except Exception as e:
        local_logger.error(f"Failed to start interface monitor: {e}")
        raise

def main(args):
    if args.daemon:
        process = start_interface_monitor()
        process.join()
    else:
        monitor = InterfaceMonitor()
        monitor.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Auto add interfaces from clickhouse")
    parser.add_argument("--daemon", type=bool, help="Run as a daemon")
    args = parser.parse_args()
    main(args)