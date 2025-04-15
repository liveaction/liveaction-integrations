import argparse
import logging
import re
import os
import ssl
import json
import urllib.request, urllib.parse
import time
import sys
import json

CURRENT_NODE_INDEX = 0
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
local_logger = logging.getLogger(__name__)

class ConfigLoader:
    def __init__(self, config_dir="config"):
        self.config_dir = config_dir
        self.interface_defaults = self._load_json("interface_defaults.json")
        self.device_defaults = self._load_json("device_defaults.json")
    
    def _load_json(self, filename):
        try:
            with open(os.path.join(self.config_dir, filename), 'r') as f:
                return json.load(f)
        except Exception as e:
            local_logger.error(f"Error loading {filename}: {str(e)}")
            return {}

config_loader = ConfigLoader()

liveNxApiHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN")

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

def get_livenx_nodes():
    '''
    {
  "meta": {
    "href": "https://35.92.47.26:8093/v1/nodes",
    "http": {
      "method": "GET",
      "statusCode": 200,
      "statusReason": "OK"
    }
  },
  "nodes": [
    {
      "id": "f081fe53-b472-4561-990c-0626918cac33",
      "name": "Local/Server",
      "ipAddress": "Local",
      "local": true,
      "state": "Connected",
      "startTime": "2024-08-13T23:25:17.866Z",
      "timeZoneId": "Etc/UTC",
      "timeStamp": "2024-08-16T00:00:00.007Z",
      "specificationsConformanceStatus": "FAIL",
      "performanceStatus": "WARNING"
    },
    {
      "id": "5bbb56cc-754b-4842-93a5-8842e1eb7a25",
      "name": "livenx-node-livenca",
      "ipAddress": "10.51.6.82",
      "local": false,
      "state": "Connected",
      "startTime": "2024-08-13T23:43:32.990Z",
      "timeZoneId": "Etc/UTC",
      "timeStamp": "2024-08-16T00:00:00.771Z",
      "specificationsConformanceStatus": "PASS",
      "performanceStatus": "OK"
    }
  ]
}
    '''
    try:
      api_url = "/v1/nodes"
      request, ctx = create_request(api_url)
      request.add_header("accept", "application/json")

      ## TO DO Try Except to handle http request timeout or exception
      with urllib.request.urlopen(request, context=ctx) as response:
          response_data = response.read().decode('utf-8')
          # Parse the JSON response
          json_data = json.loads(response_data)
          
          # Return the nodes field if it exists
          if 'nodes' in json_data:
              return json_data['nodes']
          else:
              # Handle the case where 'nodes' doesn't exist
              return []
    except Exception as err:
        local_logger.error(f"Error while call /v1/nodes: {err}")
    
    return []


def get_livenx_inventory():

    api_url = "/v1/devices"

    request, ctx = create_request(api_url)
    request.add_header("Content-Type", "application/json")
    request.add_header("accept", "application/json")
    
    # Specify the request method as POST
    request.method = "GET"

    json_data = None
    with urllib.request.urlopen(request, context=ctx) as response:
        response_data = response.read().decode('utf-8')
        # Parse the JSON response
        json_data = json.loads(response_data)
    
    return json_data

# livenx_config.py


def create_livenx_interface_from_ip(address, config_loader):
    ifcs = []
    ifc = config_loader.interface_defaults.copy()
    ifc['address'] = address
    ifcs.append(ifc)
    return ifcs

def create_livenx_device_from_ip(nodeid, ip_address, config_loader):
    livenx_device = config_loader.device_defaults.copy()
    ipNameRepresentation = ip_address.replace('.', '-')
    
    # Add required fields
    livenx_device.update({
        'nodeId': nodeid,
        'interfaces': create_livenx_interface_from_ip(ip_address, config_loader),
        'hostName': ipNameRepresentation,
        'systemName': ipNameRepresentation,
        'displaySystemName': ipNameRepresentation,
        'displayHostName': ipNameRepresentation,
        'address': ip_address
    })
    
    local_logger.debug(livenx_device)
    return livenx_device

def choose_target_node(nodes):
    global CURRENT_NODE_INDEX
    nodes = [node for node in nodes if not node.get('local', False)]  # Filter out local nodes
    if not nodes:
        return None
    CURRENT_NODE_INDEX %= len(nodes)  # Ensure index wraps around
    target_node = nodes[CURRENT_NODE_INDEX]
    CURRENT_NODE_INDEX += 1
    return target_node

def map_ip_to_livenx_inventory(ip_list):
    livenx_inventory = {}
    livenx_devices = []
    nodes = get_livenx_nodes()
    
    for ip in ip_list:
        target_node = choose_target_node(nodes)
        nodeid = target_node['id']
        livenx_devices.append(create_livenx_device_from_ip(nodeid, ip, config_loader))
    
    livenx_inventory['devices'] = livenx_devices
    return livenx_inventory

def readFile(filename=None):
    """
        Read file Method
        Parameter: filename    
    """
    if filename is None:
        local_logger.info("File name is missing")
        exit(1)
    ip_list = []
    try:
        # Read file and return
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 

        with open(filename) as rf:
            for line in rf.readlines():                
                if "received flow packet for unknown device" in line or "Flow packet received from unknown device" in line:
                    ip = ip_pattern.search(line)
                    if ip:
                        ipAddress = ip[0]
                        if ipAddress not in ip_list:
                          ip_list.append(ipAddress)
        local_logger.debug(f"List of IPs {ip_list}")
        return ip_list
    except Exception as err:
        local_logger.error(f"Error while reading log file {err}")
        return []

def add_to_livenx_inventory(livenx_inventory):

    '''
    {
  "devices": [
    {
      "nodeId": "699dbb53-1f09-4d05-f36d-0770668f510d",
      "address": "123.123.123.123",
      "systemName": "John's Device",
      "systemDescription": "Device next to John's desk in room 5207",
      "site": "NYC Office",
      "groupId": "45dc8e15-45ae-47ab-aa45-d6c944590fab",
      "groupName": "NYC Device Group",
      "stringTags": "MyTag1,MyTag2",
      "userDefinedSampleRatio": 2,
      "interfaces": [
        {
          "ifIndex": "0",
          "name": "Interface 0",
          "address": "123.123.123.123",
          "subnetMask": "255.255.255.0",
          "description": "First interface",
          "serviceProvider": "A Service Provider",
          "inputCapacity": "1000000",
          "outputCapacity": "1000000",
          "wan": false,
          "xcon": false,
          "label": "John's Interface Label",
          "stringTags": "MyTag1,MyTag2"
        }
      ]
    }
  ]
}
  
    '''

    try:
      # Convert the device list to a JSON string and encode it to bytes
      data = json.dumps(livenx_inventory).encode('utf-8')
      local_logger.info("Adding device to LiveNX {livenx_inventory}")

      # Create the request and add the Content-Type header
      request, ctx = create_request("/v1/devices/virtual", data)
      local_logger.debug(data)
      request.add_header("Content-Type", "application/json")
      request.add_header("accept", "application/json")
      # Specify the request method as POST
      request.method = "POST"
      
      with urllib.request.urlopen(request, context=ctx) as response:
          response_data = response.read().decode('utf-8')
          local_logger.debug(response_data)
    except Exception as err:
        local_logger.error(f"Error on /v1/devices/virtual API Call {err}")


def write_samplicator_config_to_file():
    try:
        #
        # 0.0.0.0/0: 10.4.205.205/2055
        # 0.0.0.0/0: 10.4.205.213/2055
        livenx_inventory = get_livenx_inventory()
        livenx_nodes = get_livenx_nodes()
        config_filename = "samplicator_config.conf"
        with open(config_filename, 'w') as config_file:
          for device in livenx_inventory.get('devices', []):
              ip_address = device.get('address')
              node_id = device.get('nodeId')
              for node in livenx_nodes:
                node_ip = node.get('ipAddress')
                if node['id'] == node_id:
                    local_logger.debug(f"Node IP: {node_ip}")
                    break
              if node_ip:
                if ip_address:
                  line = f"{ip_address}/24: {node_ip}/2055\n"
                  local_logger.debug(f"Writing line to config file: {line.strip()}")
                  config_file.write(line)
    except Exception as err:
        local_logger.error(f"Error writing out samplicator config {err}")

def main(args):
    ## trace input arguments
    local_logger.debug(args)

    if args.writesamplicatorconfig:
        # Write the samplicator config
        write_samplicator_config_to_file()
        exit(1)

    if args.logfile is None:
        local_logger.info("Missing log file")
        exit(1)
    
    if liveNxApiHost is None or liveNxApiPort is None or liveNxApiToken is None:
        local_logger.error(f"Missing env parameters: {liveNxApiHost} is None or {liveNxApiPort} is None or {liveNxApiToken} is Nonelive")
        exit(1)

    while True:
      ## Get list of IPs from log file  
      ip_list = readFile(args.logfile)
      ## Map IP to LiveNX Inventory 
      original_livenx_inventory = get_livenx_inventory()
      
      for livenx_device in original_livenx_inventory.get('devices',[]):          
        try:
          ip_list.remove(livenx_device['address'])
        except Exception as err:
            pass
      if len(ip_list) < 1:
        local_logger.debug("No IP to add")
      else:
        local_logger.debug(f"List of IPs to add: {ip_list}")   
        livenx_invenory = map_ip_to_livenx_inventory(ip_list)
        # Add IP to LiveNX
        if isinstance(livenx_invenory, dict) and len(livenx_invenory.get('devices',[])) > 0:
          add_to_livenx_inventory(livenx_invenory)
        else:
          local_logger.info("No device to add") 

      if args.continuous is False:
        break

      time.sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Auto add device to LiveNX from log file")
    parser.add_argument("--logfile", type=str, help="Add Log file")
    parser.add_argument('--continuous', action="store_true", help='Run it continuously')
    parser.add_argument('--writesamplicatorconfig', action="store_true", help='Write the samplicator config')
    args = parser.parse_args()
    main(args)
