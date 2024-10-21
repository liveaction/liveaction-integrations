import argparse
import logging
import re
import os
import ssl
import json
import urllib.request, urllib.parse

local_logger = logging.getLogger(__name__)

liveNxHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxToken = os.getenv("LIVENX_API_TOKEN")
liveNxTargetIP = os.getenv("LIVENX_TARGET_IP")

def create_request(url, data = None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "Authorization": "Bearer " + liveNxToken
    }
    api_url = "https://" + liveNxHost + ":" + liveNxApiPort + url

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
    
    return []

def create_livenx_interface_from_ip(address):
    '''
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
    
    '''
    ifcs = []
    ifc = {}
    ifc['ifIndex'] = '0'
    ifc['name'] = 'ge0/0'
    ifc['address'] = address
    ifc['subnetMask'] = '255.255.255.0'
    ifc['description'] = ''
    ifc['serviceProvider'] = ''
    ifc['inputCapacity'] = "1000000"
    ifc['outputCapacity'] = "1000000"
    ifc['wan'] = False
    ifc['xcon'] = False
    ifc['label'] = ''
    ifc['stringTags'] = ''
    ifcs.append(ifc)
    return ifcs

def create_livenx_device_from_ip(nodeid, ip_address):
    """
        {
            "ipAddress": "10.0.3.1",
            "hostname": "C2611",
            "adapterId": "Cisco::IOS",
            "deviceType": "Router",
            "hardwareVendor": "Cisco",
            "model": "CISCO2611",
            "softwareVendor": "Cisco",
            "osVersion": "12.1(19)",
            "backupStatus": "SUCCESS",
            "complianceState": 0,
            "lastBackup": 1410324616600,
            "lastTelemetry": null,
            "memoSummary": null,
            "custom1": "",
            "custom2": "",
            "custom3": "",
            "custom4": "",
            "custom5": "",
            "network": "Default",
            "serialNumber": "JAB03060AX0"
         },
    """
    livenx_device = {}
    livenx_device['nodeId'] = nodeid
    livenx_device['interfaces'] = create_livenx_interface_from_ip(ip_address)
    livenx_device['hostName'] = ip_address
    livenx_device['systemName'] = ip_address
    livenx_device['systemDescription'] = ''
    livenx_device['address'] = ip_address
    livenx_device['site'] = ''
    #livenx_device['groupId'] = str(uuid.uuid4())
    #livenx_device['groupName'] = ""
    livenx_device['stringTags'] = ""
    livenx_device['userDefinedSampleRatio'] = 2
    local_logger.info(livenx_device)
    return livenx_device


def map_ip_to_livenx_inventory(ip_list):
    livenx_inventory = {}
    livenx_devices = []
    nodes = get_livenx_nodes()
    node = None
    for node in nodes:
      if node['ipAddress'] == liveNxTargetIP:
        nodeid = node['id']
        break
    if node == None:
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
                if "Flow packet received from unknown device" in line:
                    ip = ip_pattern.search(line)
                    if ip:
                        ip_list.append(ip[0])
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


def main(args):
    ## trace input arguments
    local_logger.info(args)

    if args.logfile is None:
        local_logger.info("Missing log file")
        exit(1)

    ## Get list of IPs from log file  
    ip_list = readFile(args.logfile)
    ## Map IP to Linenx Inventory 
    livenx_invenory = map_ip_to_livenx_inventory(ip_list)
    ## Add IP to LiveNX 
    add_to_livenx_inventory(livenx_invenory)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Auto add device to LiveNX from log file")
    parser.add_argument("--logfile", type=str, help="Add Log file")
    args = parser.parse_args()
    main(args)