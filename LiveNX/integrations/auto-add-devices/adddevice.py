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

local_logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

liveNxApiHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN")
liveNxTargetIP = os.getenv("LIVENX_TARGET_NODE_IP")

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
    
    local_logger.info(livenx_device)
    return livenx_device


def map_ip_to_livenx_inventory(ip_list):
    livenx_inventory = {}
    livenx_devices = []
    nodes = get_livenx_nodes()
    node = None
    nodeid = None
    for node in nodes:
      if node['ipAddress'] == liveNxTargetIP:
        nodeid = node['id']
        break
    if nodeid == None:
        local_logger.info(f"Node Id doesnot match with liveNx Target IP")
        return 
    for ip in ip_list:
        livenx_devices.append(create_livenx_device_from_ip(nodeid, ip))
    
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
        local_logger.info(f"List of IPs {ip_list}")
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

      # Create the request and add the Content-Type header
      request, ctx = create_request("/v1/devices/virtual", data)
      local_logger.info(data)
      request.add_header("Content-Type", "application/json")
      request.add_header("accept", "application/json")
      # Specify the request method as POST
      request.method = "POST"
      
      with urllib.request.urlopen(request, context=ctx) as response:
          response_data = response.read().decode('utf-8')
          local_logger.info(response_data)
    except Exception as err:
        local_logger.error(f"Error on /v1/devices/virtual API Call {err}")


def main(args):
    ## trace input arguments
    local_logger.info(args)

    if args.logfile is None:
        local_logger.info("Missing log file")
        exit(1)
    
    if liveNxApiHost is None or liveNxApiPort is None or liveNxApiToken is None or liveNxTargetIP is None:
        local_logger.error(f"Missing env parameters: {liveNxApiHost} is None or {liveNxApiPort} is None or {liveNxApiToken} is None or {liveNxTargetIP}")
        exit(1)

    while True:
      ## Get list of IPs from log file  
      ip_list = readFile(args.logfile)
      ## Map IP to Linenx Inventory 
      orginal_livenx_inventory = get_livenx_inventory()
      for livenx_device in orginal_livenx_inventory.get('devices',[]):          
        try:
          ip_list.remove(livenx_device['address'])
        except Exception as err:
            pass
      if len(ip_list) < 1:
        local_logger.info("No IP to add")
      else:
        local_logger.info(f"List of IPs to add: {ip_list}")   
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
    args = parser.parse_args()
    main(args)