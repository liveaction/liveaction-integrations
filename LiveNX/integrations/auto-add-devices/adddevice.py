import argparse
import logging
import re
import os
import json
import urllib.request
import time
import sys
import json
import gzip
import time
from helper.livenx import create_request
from helper.livenx import get_livenx_inventory, get_livenx_nodes, get_livenx_node_id_from_ip, delete_livenx_device
import ipaddress
from collections import defaultdict

from autoaddinterfaces import InterfaceMonitor



liveNxApiHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN")

SAMPLICATOR_SERVER_PORT = int(os.getenv("SAMPLICATOR_SERVER_PORT", "2054"))
SAMPLICATOR_NODE_PORT = int(os.getenv("SAMPLICATOR_NODE_PORT", "2055"))

CURRENT_NODE_INDEX = 0
logging.basicConfig(stream=sys.stdout,
    level=os.environ.get('LOGLEVEL', 'INFO').upper()
)
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


# livenx_config.py
def move_device(device, new_node_id):
    """
    Move a device from one node to another.
    This function is a placeholder and should be implemented based on your specific requirements.
    """
    # Update the device's node ID in the inventory

    local_logger.debug(f"Moving device {device['hostName']} to node {new_node_id}")
    '''Example device:    {
      "meta": {
        "href": "string",
        "queryParameters": {
          "additionalProp1": [
            "string"
          ],
          "additionalProp2": [
            "string"
          ],
          "additionalProp3": [
            "string"
          ]
        },
        "http": {
          "method": "string",
          "statusCode": 0,
          "statusReason": "string"
        }
      },
      "href": "https://10.10.10.10:8093/v1/devices/9IRVE649AQF",
      "id": "9IRVE649AQF",
      "serial": "9IRVE649AQF",
      "address": "1.1.1.1",
      "clientIp": "10.10.10.10",
      "systemName": "device.test.com",
      "displaySystemName": "device.test.com [10.10.10.10 | Node1 | 9IRVE649AQF]",
      "hostName": "device",
      "displayHostName": "device [10.10.10.10 | Node1 | 9IRVE649AQF]",
      "systemLocation": "West Coast Office",
      "systemDescription": "Gigabit Routing Switch",
      "nodeId": "843bf835-e330-45fc-a363-c407237ef4d7",
      "osVersion": {
        "majorNumber": 12,
        "minorNumber": 1,
        "indivNumber": null,
        "indivNumberSuffix": null,
        "newFeatureIdentifier": null,
        "newFeatureVersion": null,
        "versionString": null,
        "osType": "IOS_XE"
      },
      "osVersionString": "12.1",
      "vendorProduct": {
        "model": "ciscoCSR1000v",
        "displayName": "ciscoCSR1000v",
        "description": "ciscoCSR1000v",
        "vendor": {
          "vendorName": "Cisco",
          "vendorOid": {
            "displayName": ".1.3.6.1.4.1.9"
          },
          "vendorSerialOid": {
            "displayName": ".1.3.6.1.4.1.9.3.6.3"
          }
        },
        "objectOID": {
          "displayName": ".1.3.6.1.4.1.9.1.1537"
        },
        "objectOIDString": ".1.3.6.1.4.1.9.1.1537",
        "asrModel": false
      },
      "site": "Western Division",
      "isDataCenterSite": false,
      "tags": [
        "Corp",
        "West"
      ],
      "taggedOmni": false,
      "interfaces": {
        "name": "Null0",
        "abbreviatedName": "Nu0",
        "ifIndex": 5,
        "description": "",
        "speed": 10000000000,
        "type": "other",
        "wan": false,
        "xcon": false,
        "interfaceState": "UP"
      },
      "monitorOnly": false,
      "settings": {
        "pollInterval": 60000,
        "enablePoll": true,
        "enableQosPoll": true,
        "enableNetflowPoll": true,
        "enableIpslaPoll": true,
        "enableLanPoll": true,
        "enableRoutingPoll": true,
        "virtualDevice": false
      },
      "capabilities": {
        "nbarCapable": true,
        "netflowCollectorCapable": true,
        "mediatraceCapable": true,
        "extendedTraceRouteCapable": true,
        "nbar2Capable": true,
        "flexibleNetflowCapable": true,
        "perfmonCapable": true,
        "avcCapable": false,
        "unifiedPerfmonCapable": true,
        "hqfSupportDetected": true,
        "ipslaCapable": true
      },
      "pollingSupported": {
        "netflowPollingSupported": true,
        "ipslaPollingSupported": true,
        "lanPollingSupported": true,
        "routingPollingSupported": true,
        "qosPollingSupported": true
      },
      "group": {
        "idString": "7e3cf778-770d-41fe-932d-f3cf12902e61"
      },
      "linkInfo": {
        "type": "OMNI_PEEK",
        "label": "Packet Inspection",
        "displayValue": "Peek",
        "rawValue": {
          "name": "OmniPeek Web",
          "host": "10.4.201.132",
          "path": "/omnipeek/forensics",
          "startTime": "2023-03-08T02:08:10.000Z",
          "endTime": "2023-03-08T02:13:10.000Z",
          "showDialog": true
        }
      },
      "analyticsNode": "Analytics Node",
      "state": "NOT_AVAILABLE",
      "userDefinedSampleRatio": 100,
      "deviceLoadedState": "NOT_AVAILABLE"
    }'''
    '''"config": {
        "nodeId": "45dc8e15-45ae-47ab-aa45-d6c944590fab",
        "systemName": "John's Device",
        "systemDescription": "Device next to John's desk in room 5207",
        "pollInterval": 60000,
        "enablePoll": true,
        "enableQosPoll": false,
        "enableNetflowPoll": true,
        "enableIpslaPoll": false,
        "enableLanPoll": false,
        "enableRoutingPoll": false,
        "groupId": "45dc8e15-45ae-47ab-aa45-d6c944590fab",
        "groupName": "NYC Device Group",
        "stringTags": "WAN,EastCoast",
        "site": "NYC Office",
        "siteIpRanges": "123.123.123.0/25",
        "isDataCenterSite": false,
        "userDefinedSampleRatio": 2,
        "probeIPAddress": "123.123.123.123",
        "ipAddress": "123.123.123.123"
      }'''
    device_spec = {}
    device_spec['deviceSerial'] = device['serial']
    device_config_json = {}
    device_config_json['nodeId'] = new_node_id
    device_config_json['systemName'] = device.get('systemName', "")
    device_config_json['systemDescription'] = device.get('systemDescription', "")
    device_config_json['pollInterval'] = device.get('pollInterval', 60000)
    device_config_json['enablePoll'] = device.get('enablePoll', True)
    device_config_json['enableQosPoll'] = device.get('enableQosPoll', False)
    device_config_json['enableNetflowPoll'] = device.get('enableNetflowPoll', True)
    device_config_json['enableIpslaPoll'] = device.get('enableIpslaPoll', False)
    device_config_json['enableLanPoll'] = device.get('enableLanPoll', False)
    device_config_json['enableRoutingPoll'] = device.get('enableRoutingPoll', False)
    device_config_json['groupId'] = device.get('groupId', "")
    device_config_json['groupName'] = device.get('groupName', "")
    tags = device.get('tags', [])
    stringTags = tags if isinstance(tags, str) else ','.join(tags)
    device_config_json['stringTags'] = stringTags
    device_config_json['site'] = device.get('site', "")
    device_config_json['siteIpRanges'] = device.get('siteIpRanges', "")
    device_config_json['isDataCenterSite'] = device.get('isDataCenterSite', False)
    device_config_json['userDefinedSampleRatio'] = device.get('userDefinedSampleRatio', 1)
    device_config_json['probeIPAddress'] = device.get('address', "")                    
    device_config_json['ipAddress'] = device.get('address', "")
    device_spec['config'] = device_config_json
    return device_spec


def consolidate_devices(devices):
    """
    Consolidate devices by merging devices that have any interface with the same address. 
    The non-SNMP device will be deleted and the SNMP device that has the same address will be moved to the same LiveNX node as the non-SNMP device.
    """
    consolidated_devices = []
    for device in devices:
        # Go through the interfaces of the devices to see if any inteface on any other device has the same address
        for interface in device.get('interfaces', []):
            address = interface.get('address')
            if address:
                # Go through the rest of the devices to see if any other device interfaces has the same address
                for other_device in devices:
                    if other_device['id'] != device['id']:
                        for other_interface in other_device.get('interfaces', []):
                            other_address = other_interface.get('address')
                            if other_address == address:
                                # delete the non-SNMP device and move the SNMP device to the same LiveNX node as the non-SNMP device
                                if device['settings'].get('virtualDevice', False):
                                    # This is a non-SNMP device, so we will delete it
                                    local_logger.debug(f"Deleting non-SNMP device {device['id']} with address {address}")
                                    delete_livenx_device(device['serial'])
                                    # Move the SNMP device to the same LiveNX node as the non-SNMP device
                                    if other_device.get('nodeId') != device.get('nodeId'):
                                        other_device['nodeId'] = device['nodeId']
                                        consolidated_devices.append(other_device)                             
                                break
    
    # Go tthrough the devices and call move_device on each device that has been consolidated
    for device in consolidated_devices:
        new_node_id = device.get('nodeId')
        local_logger.debug(f"Consolidating device {device['hostName']} to node {new_node_id}")
        move_device(device, new_node_id)

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
    nodes = [node for node in nodes]
    if not nodes:
        return None
    CURRENT_NODE_INDEX %= len(nodes)  # Ensure index wraps around
    target_node = nodes[CURRENT_NODE_INDEX]
    CURRENT_NODE_INDEX += 1
    return target_node

def map_ip_to_livenx_inventory(ip_list, include_server=False):
    livenx_inventory = {}
    livenx_devices = []
    nodes = get_livenx_nodes(include_server=include_server)
    
    for ip in ip_list:
        target_node = choose_target_node(nodes)
        nodeid = target_node['id']
        livenx_devices.append(create_livenx_device_from_ip(nodeid, ip, config_loader))
    
    livenx_inventory['devices'] = livenx_devices
    return livenx_inventory

    
def read_samplicator_ip_file(filename=None):
    """
        Read file Method
        Parameter: filename    
    """
    if filename is None:
        local_logger.info("File name is missing")
        exit(1)
    ip_set = set()  # Use a set to avoid duplicates
    try:
        # Check if the file is gzipped
        open_func = gzip.open if filename.endswith('.gz') else open

        with open_func(filename, 'rt') as rf:  # 'rt' mode for reading text
            for line in rf.readlines():
                ip_set.add(line.strip())
        local_logger.debug(f"Number of IPs from Samplicator {len(ip_set)}")
        return ip_set
    except Exception as err:
        local_logger.error(f"Error while reading log file {err}")
        return ip_set

def add_to_livenx_inventory(livenx_inventory, urlpath="/v1/devices/virtual", request_method="POST"):

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
      "userDefinedSampleRatio": 1,
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

    for attempt in range(3):  # Retry up to 3 times
        try:
            # Convert the device list to a JSON string and encode it to bytes
            data = json.dumps(livenx_inventory).encode('utf-8')
            local_logger.debug(f"Adding device to LiveNX {livenx_inventory}")

            # Create the request and add the Content-Type header
            request, ctx = create_request(urlpath, data)
            local_logger.debug(data)
            request.add_header("Content-Type", "application/json")
            request.add_header("accept", "application/json")
            # Specify the request method as POST
            request.method = request_method

            with urllib.request.urlopen(request, context=ctx) as response:
                response_data = response.read().decode('utf-8')
                local_logger.debug(response_data)
            break  # Exit the loop if the request is successful
        except Exception as err:
            local_logger.error(f"Error on /v1/devices/virtual API Call (Attempt {attempt + 1}/3): {err}")
            if attempt < 2:  # Only sleep if this is not the last attempt
                time.sleep(5)

def group_ips_into_subnets(ip_list, max_subnets=1000, init_prefix_len=32):
    """
    Group IP addresses into the smallest possible subnets while keeping
    the total number of subnets under the specified maximum.
    
    Args:
        ip_list (list): List of IP address strings
        max_subnets (int): Maximum number of subnets to create (default 1000)
        
    Returns:
        list: List of subnet strings in CIDR notation
    """
    # Convert all IPs to IPv4Address objects and create a set for fast lookups
    ip_objects = [ipaddress.IPv4Address(ip) for ip in ip_list]
    ip_set = set(ip_objects)
    
    # Continue merging until we get under the max_subnets limit
    current_prefix_len = init_prefix_len

    # Start with /32 (individual IP) subnets
    subnets = {ipaddress.IPv4Network(f"{ip}/{current_prefix_len}", strict=False) for ip in ip_objects}
    
    # If we have fewer subnets than the max, we can return immediately
    if len(subnets) <= max_subnets:
        return [str(subnet) for subnet in subnets]
    
    while len(subnets) > max_subnets and current_prefix_len > 0:
        current_prefix_len -= 1
        
        # Group subnets by their potential supernet with the new prefix length
        potential_subnets = defaultdict(list)
        for subnet in subnets:
            # Calculate the supernet that would contain this subnet
            supernet = ipaddress.IPv4Network(
                f"{subnet.network_address}/{current_prefix_len}", strict=False
            )
            potential_subnets[supernet].append(subnet)
        
        # Replace groups of subnets with their supernets where possible
        new_subnets = set()
        ip_set_remaining = set(ip_set)
        for supernet, contained_subnets in potential_subnets.items():
            new_subnets.add(supernet)
            if len(new_subnets) > max_subnets:
                # If we exceed the max_subnets, we need to stop
                break
            # Calculate the number of IPs in our original set that are inside this supernet
            for ip in ip_set:
                if ip in supernet:
                    # Remove the IP from the remaining set
                    ip_set_remaining.remove(ip)
                    if len(ip_set_remaining) == 0:
                        break
        
        if len(ip_set_remaining) == 0 and len(new_subnets) <= max_subnets:
            # If we're now under the limit, we can stop
            subnets = new_subnets
            break
        
    
    # Convert subnets to strings
    return [str(subnet) for subnet in subnets]

def move_devices(subnets, livenx_inventory, node_ips, include_server=False):
    modified_devices = []
    nodes = get_livenx_nodes(include_server=include_server)
    try:
        # check every device to see if the node ip it was previously assigned to has changed
        for device in livenx_inventory.get('devices', []):
            device_ip = device.get('address')
            if device_ip:
                # Sort subnets by prefix length (smallest subnets first)
                sorted_subnets = sorted(subnets, key=lambda subnet: ipaddress.ip_network(subnet).prefixlen, reverse=True)

                # Check if the device IP is in the smallest matching subnet
                for subnet in sorted_subnets:
                    if ipaddress.ip_address(device_ip) in ipaddress.ip_network(subnet):
                        # If it is, update the node IP for that device
                        new_node_ip = node_ips[sorted_subnets.index(subnet) % len(node_ips)]
                        current_device_node_id = device.get('nodeId')
                        new_node_id = get_livenx_node_id_from_ip(nodes, new_node_ip)
                        if current_device_node_id != new_node_id:
                            local_logger.debug(f"Moving device {device['hostName']} from node {current_device_node_id} to node {new_node_id}")
                            move_device(device, new_node_id)
                        else:
                            local_logger.debug(f"Not moving device {device['hostName']}")
                        break

        # If there are modified devices, update them in LiveNX
        if len(modified_devices) > 0:
            # chunk the devices to avoid memory issues
            chunk_size = 10
            livenx_inventory = {}
            for i in range(0, len(modified_devices), chunk_size):
                chunk = modified_devices[i:i + chunk_size]
                livenx_inventory['devices'] = chunk
                add_to_livenx_inventory(livenx_inventory, urlpath="/v1/devices/config", request_method="PUT")

    except Exception as err:
        local_logger.error(f"Error moving devices: {err}")
    return modified_devices

def restart_samplicator(samplicatorfilepath, samplicatorconfigfilepath, montoripfile, samplicatorhost, samplicatorport):
    """
    Restart the Samplicator service.
    """
    try:
        stop_samplicator()
        start_samplicator(samplicatorfilepath, samplicatorconfigfilepath, montoripfile, samplicatorhost, samplicatorport)
    except Exception as err:
        local_logger.error(f"Error while restarting Samplicator: {err}")

def stop_samplicator():
    """
    Restart the Samplicator service.
    """
    try:
        # run killall samplicate command
        local_logger.info("Killing all Samplicator processes...")
        os.system("killall samplicate")
    except Exception as err:
        local_logger.error(f"Error while restarting Samplicator: {err}")

def start_samplicator(samplicatorfilepath, samplicatorconfigfilepath, montoripfile, samplicatorhost="127.0.0.1", samplicatorport=2055):
    """
    Start the Samplicator service.
    """
    try:
        local_logger.info("Starting samplicator service...")
        # run the restart command
        if os.path.exists(samplicatorconfigfilepath) == False:
            # create an empty file
            with open(samplicatorconfigfilepath, 'w') as f:
                f.write("1.2.3.4/255.255.255.255: 127.0.0.1/9999")
                f.close()
        
        os.system(f"{samplicatorfilepath} -n -o -S -c {samplicatorconfigfilepath} -i {montoripfile} -p {samplicatorport} -s {samplicatorhost} -f")
    except Exception as err:
        local_logger.error(f"Error while restarting Samplicator: {err}")

def write_samplicator_config_to_files(samplicator_config_file_path, max_subnets, movedevices, include_server):
    should_restart_samplicator = False
    try:
        livenx_inventory = get_livenx_inventory()
        livenx_nodes = get_livenx_nodes(include_server=include_server)
        ip_addresses = []

        # Collect all IP addresses from the inventory
        for device in livenx_inventory.get('devices', []):
            ip_address = device.get('address')
            if ip_address:
                ip_addresses.append(ip_address)

        # Group IPs into subnets
        subnets = group_ips_into_subnets(ip_addresses, max_subnets=max_subnets)

        # Ensure we have node IPs to distribute subnets
        node_ips = [node.get('ipAddress') for node in livenx_nodes if node.get('ipAddress')]
        if not node_ips:
            local_logger.error("No node IPs available for distribution.")
            return

        # Distribute subnets evenly across node IPs
        with open(samplicator_config_file_path, 'w') as config_file:
            for i, subnet in enumerate(subnets):
                node_ip = node_ips[i % len(node_ips)]  # Cycle through node IPs
                ip = str(ipaddress.ip_network(subnet)).split('/')[0]
                dotted_notation = str(ipaddress.ip_network(subnet).netmask)
                samplicator_port = SAMPLICATOR_NODE_PORT
                if node_ip == '127.0.0.1':
                    samplicator_port = SAMPLICATOR_SERVER_PORT
                line = f"{ip}/{dotted_notation}: {node_ip}/{samplicator_port}\n"
                local_logger.debug(f"Writing line to config file: {line.strip()}")
                config_file.write(line)

        if movedevices:
            modified_devices = move_devices(subnets, livenx_inventory, node_ips, include_server=include_server)
            if len(modified_devices) > 0:
                local_logger.debug(f"Moved devices: {modified_devices}")
                should_restart_samplicator = True
    except Exception as err:
        local_logger.error(f"Error writing out samplicator config: {err}")

    return should_restart_samplicator

def add_test_devices(start_num, num_devices, include_server=False):
    try:
        livenx_inventory = {}
        livenx_devices = []
        nodes = get_livenx_nodes(include_server=include_server)
        
        for i in range(start_num, start_num + num_devices):
            # Generate IP addresses across a larger range (10.x.x.x)
            octet1 = 10
            octet2 = (i // (256 * 256)) % 256  # Second octet
            octet3 = (i // 256) % 256          # Third octet
            octet4 = i % 256                   # Fourth octet
            ip_address = f"{octet1}.{octet2}.{octet3}.{octet4}"
            
            target_node = choose_target_node(nodes)
            if not target_node:
                local_logger.error("No available target nodes to assign devices.")
                break
            
            nodeid = target_node['id']
            livenx_devices.append(create_livenx_device_from_ip(nodeid, ip_address, config_loader))
            
            # Add devices in chunks of 10 to avoid memory issues
            if len(livenx_devices) >= 10 or i == start_num + num_devices - 1:
                livenx_inventory['devices'] = livenx_devices
                add_to_livenx_inventory(livenx_inventory)
                livenx_devices = []  # Reset the list for the next batch

    except Exception as err:
        local_logger.error(f"Error adding test devices: {err}")

def monitor_samplicator_ip_file(filename, include_server=False):
    """
    Monitor a log file for IP addresses and add them to LiveNX.
    """
    local_logger.debug(f"Monitoring {filename} for IP addresses.")
    ip_set = read_samplicator_ip_file(filename)
    local_logger.debug(f"Set of IPs from log file {filename} {ip_set}")
    
    if len(ip_set) < 1:
        local_logger.debug("No IP to add")
    else:
        # get existing livenx inventory
        original_livenx_inventory = get_livenx_inventory()
        local_logger.debug(f"Number of IPs from Samplicator IP file: {len(ip_set)}")
        local_logger.debug(f"Number of IPs from LiveNX: {len(original_livenx_inventory.get('devices', []))}")
        
        new_device_inventory = None
        # Remove existing IPs from the list
        for livenx_device in original_livenx_inventory.get('devices',[]):
            try:
              local_logger.debug(f"Removing IP {livenx_device['address']} from list")
              ip_set.remove(livenx_device['address'])
            except Exception as err:
                local_logger.error(f"Error removing IP {livenx_device['address']} from list: {err}")
                pass
        local_logger.debug(f"Set of IPs after removing existing devices: {ip_set}")
        if len(ip_set) < 1:
            local_logger.debug("No IP to add")
        else:  
            ip_list = list(ip_set)              
            for i in range(0, len(ip_list), 10):  # Process in chunks of 10
                chunk = ip_list[i:i + 10]
                new_device_inventory = map_ip_to_livenx_inventory(chunk, include_server=include_server)
                # Add IP to LiveNX
                if isinstance(new_device_inventory, dict) and len(new_device_inventory.get('devices', [])) > 0:
                    add_to_livenx_inventory(new_device_inventory)
                else:
                    local_logger.debug("No device to add")
    return len(ip_set)


def main(args):
    ## trace input arguments
    local_logger.debug(args)

    if args.restartsamplicator:
        restart_samplicator(args.samplicatorpath, args.samplicatorconfigfilepath, args.monitoripfile, args.samplicatorhost, args.samplicatorport)
        exit(0)

    if args.monitoripfile is not None:
        restart_samplicator(args.samplicatorpath, args.samplicatorconfigfilepath, args.monitoripfile, args.samplicatorhost, args.samplicatorport)
        last_added_time = 0.0
        last_autoadded_interface_time = time.time()
        current_time = 0.0
        while True:
            try:
                # check if the file exists
                if os.path.exists(args.monitoripfile):

                    # Check if the file has been modified since the last check
                    current_time = time.time()
                    num_devices_added = monitor_samplicator_ip_file(args.monitoripfile, args.includeserver)
                    if num_devices_added > 0:
                        last_added_time = current_time

                local_logger.debug(f"No new devices added since {int(time.time() - last_added_time)} seconds ({int(last_added_time)}). Will rebalance after no device added for {args.numsecstowaitbeforerebalance} seconds.")
                # If the last added time is older than 5 minutes, move the devices
                if last_added_time > 0.0 and (time.time() - last_added_time) > int(args.numsecstowaitbeforerebalance):                     

                    if args.writesamplicatorconfigmaxsubnets is not None and args.movedevices:
                        local_logger.info(f"File {args.monitoripfile} has not been modified for {args.numsecstowaitbeforerebalance} seconds. Running rebalance operation.")
                        # Move devices if needed
                        should_restart_samplicator = write_samplicator_config_to_files(args.samplicatorconfigfilepath, args.writesamplicatorconfigmaxsubnets, args.movedevices, args.includeserver)

                        if should_restart_samplicator:
                            # Restart the Samplicator service
                            restart_samplicator(args.samplicatorpath, args.samplicatorconfigfilepath, args.monitoripfile, args.samplicatorhost, args.samplicatorport)
                    last_added_time = 0.0

                # Run the autoadd interfaces every 5 minutes
                if args.addinterfaces and (time.time() - last_autoadded_interface_time) > args.numsecstowaitbeforeaddinginterfaces:
                    local_logger.info(f"Last autoadded interface waittime expired ({args.numsecstowaitbeforeaddinginterfaces} seconds). Running auto add interfaces operation.")
                    interface_monitor = InterfaceMonitor()
                    interface_monitor.run_one_cycle()                        
                    last_autoadded_interface_time = time.time()

                time.sleep(60)  # Sleep for a while before checking again
            except KeyboardInterrupt:
                local_logger.info("Monitoring interrupted by user.")
                break
            except Exception as e: 
                local_logger.error(f"Error while monitoring IP file: {e}")
                time.sleep(60)
                continue
        exit(0)

    if args.addtestdevices is not None and args.addtestdevices > 0:
        # Write outtest devices
        add_test_devices(args.addtestdevicesstartnum, args.addtestdevices, args.includeserver)
        exit(0)

    if args.writesamplicatorconfig:
        # Write the samplicator config
        write_samplicator_config_to_files(args.samplicatorconfigfilepath, args.writesamplicatorconfigmaxsubnets, args.movedevices, args.includeserver)
        exit(0)

    if liveNxApiHost is None or liveNxApiPort is None or liveNxApiToken is None:
        local_logger.error(f"Missing env parameters: {liveNxApiHost} is None or {liveNxApiPort} is None or {liveNxApiToken} is Nonelive")
        exit(0)



def test_group_ips_into_subnets():
    """
    Tests the group_ips_into_subnets function with various scenarios.
    """
    # Import the function if it's in another module
    # from your_module import group_ips_into_subnets
    
    # Test case 1: Empty list
    result = group_ips_into_subnets([])
    assert result == [], "Empty input should return empty list"
    
    # Test case 2: Single IP
    result = group_ips_into_subnets(["192.168.1.1"])
    assert result == ["192.168.1.1/32"], "Single IP should return single /32 subnet"
    
    # Test case 3: IPv6 address
    #result = group_ips_into_subnets(["2001:db8::1"])
    #assert result == ["2001:db8::1/128"], "IPv6 address should return single /128 subnet"
    
    # Test case 4: Mixed IPv4 and IPv6
    #result = group_ips_into_subnets(["192.168.1.1", "2001:db8::1"])
    #assert set(result) == {"192.168.1.1/32", "2001:db8::1/128"}, "Mixed IP versions should work"
    
    # Test case 5: Duplicate IPs
    result = group_ips_into_subnets(["192.168.1.1", "192.168.1.1", "192.168.1.1"])
    assert result == ["192.168.1.1/32"], "Duplicate IPs should be removed"
    
    # Test case 6: Sequential IPs that can be merged
    result = group_ips_into_subnets(["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"], max_subnets=1)
    assert result == ["192.168.1.0/30"], "Sequential IPs should merge into a single subnet"
    
    # Test case 7: IPs that cannot be perfectly merged
    result = group_ips_into_subnets(["192.168.1.1", "192.168.1.3", "192.168.1.5", "192.168.1.7"], max_subnets=1)
    assert result == ["192.168.1.0/29"], "Non-sequential IPs should merge into smallest containing subnet"
    
    # Test case 8: Force merge with max_subnets
    large_list = [f"192.168.{i}.{j}" for i in range(10) for j in range(10)]  # 100 IPs
    result = group_ips_into_subnets(large_list, max_subnets=5)
    assert len(result) <= 5, f"Result should have at most 5 subnets, got {len(result)}"
    
    # Test case 10: Different IP blocks
    result = group_ips_into_subnets(["10.0.0.1", "10.1.1.1", "172.16.0.1", "192.168.1.1"], max_subnets=3)
    assert set(result) == {"10.0.0.0/8", "172.16.0.1/32", "192.168.1.1/32"}, "Different IP blocks should remain separate"
    
    # Test case 11: Max subnets larger than needed
    result = group_ips_into_subnets(["192.168.1.1", "192.168.1.2"], max_subnets=10)
    assert len(result) <= 10, "Should respect max_subnets even when not needed"
    
    # Test case 13: Very large number of IPs
    # This is a more intensive test - comment out if performance is a concern
    large_ip_list = [f"10.{i}.{j}.{k}" for i in range(5) for j in range(5) for k in range(5)]  # 125 IPs
    result = group_ips_into_subnets(large_ip_list, max_subnets=10)
    assert len(result) <= 10, f"Should handle large lists and respect max_subnets, got {len(result)}"
    
    # Test case 14: Verify all original IPs are covered by resulting subnets
    test_ips = ["192.168.1.1", "192.168.1.5", "10.0.0.1"]
    result = group_ips_into_subnets(test_ips, max_subnets=2)
    assert len(result) <= 2, "Should respect max_subnets constraint"
    
    # Convert result subnets to ipaddress objects
    result_networks = [ipaddress.ip_network(subnet) for subnet in result]
    
    # Check that each original IP is contained in at least one of the result subnets
    for ip_str in test_ips:
        ip = ipaddress.ip_address(ip_str)
        is_contained = any(ip in network for network in result_networks)
        assert is_contained, f"IP {ip} should be contained in at least one subnet"
    
    print("All tests passed!")


if __name__ == "__main__":
    #test_group_ips_into_subnets()
    #exit(1)
    parser = argparse.ArgumentParser(description="Process Auto add device to LiveNX from samplicator log file.")
    parser.add_argument('--writesamplicatorconfig', action="store_true", help='Write the samplicator config')
    parser.add_argument('--samplicatorpath', type=str, help='Samplicator path')
    parser.add_argument('--samplicatorconfigfilepath', type=str, help='Samplicator config file path')
    parser.add_argument('--samplicatorhost', type=str, help='Samplicator host')
    parser.add_argument('--samplicatorport', type=int, help='Samplicator port')
    parser.add_argument('--restartsamplicator', action="store_true", help='Restart samplicator if needed')
    parser.add_argument('--movedevices', action="store_true", help='Move the devices between nodes if needed')
    parser.add_argument('--includeserver', action="store_true", help='Include the server in the device list')
    parser.add_argument('--addinterfaces', action="store_true", help='Add interfaces to the devices')
    parser.add_argument('--writesamplicatorconfigmaxsubnets', type=int, help='The maximum number of subnets to write out to the config file')
    parser.add_argument('--addtestdevices', type=int, help='Add a number of test devices starting at 10.x.x.x.')
    parser.add_argument('--addtestdevicesstartnum', type=int, help='The starting index number for the test devices at 10.x.x.x.')
    parser.add_argument('--monitoripfile', type=str, help='The log file to monitor for IP addresses')
    parser.add_argument('--numsecstowaitbeforerebalance', nargs='?', const=300, type=int, default=300)
    parser.add_argument('--numsecstowaitbeforeaddinginterfaces', nargs='?', const=300, type=int, default=300)
    args = parser.parse_args()
    main(args)
