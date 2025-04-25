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
from helper.livenx import get_livenx_inventory

liveNxApiHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN")

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
              nodes = json_data['nodes']
              ret_nodes = []
              for node in nodes:
                  # Check if the node is local
                  print(node)
                  if node.get('local', False) == False:
                      ret_nodes.append(node)
              return ret_nodes
          else:
              # Handle the case where 'nodes' doesn't exist
              return []
    except Exception as err:
        local_logger.error(f"Error while call /v1/nodes: {err}")
    
    return []


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
    local_logger.info(f"MONITORING {filename}")
    ip_list = []
    try:
        # Read file and return
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 

        # Check if the file is gzipped
        open_func = gzip.open if filename.endswith('.gz') else open

        with open_func(filename, 'rt') as rf:  # 'rt' mode for reading text
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
            local_logger.info(f"Adding device to LiveNX {livenx_inventory}")

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
            break  # Exit the loop if the request is successful
        except Exception as err:
            local_logger.error(f"Error on /v1/devices/virtual API Call (Attempt {attempt + 1}/3): {err}")
            if attempt < 2:  # Only sleep if this is not the last attempt
                time.sleep(5)


import ipaddress
from typing import List, Set


def group_ips_into_subnets(ip_addresses: List[str], max_subnets: int = 2000) -> List[str]:
    """
    Groups a list of IP addresses into subnets, ensuring the total number of subnets
    doesn't exceed the specified maximum.
    
    Args:
        ip_addresses: List of IP address strings
        max_subnets: Maximum number of subnets to generate (default: 2000)
        
    Returns:
        List of subnet strings in CIDR notation
    """
    # Convert string IPs to ipaddress objects and remove duplicates
    unique_ips = set()
    for ip in ip_addresses:
        try:
            unique_ips.add(ipaddress.ip_address(ip.strip()))
        except ValueError:
            print(f"Warning: Invalid IP address ignored: {ip}")
    
    # Sort IPs numerically
    sorted_ips = sorted(unique_ips)
    
    if not sorted_ips:
        return []
    
    # Start with single IP subnets (maximum specificity)
    subnets = []
    for ip in sorted_ips:
        if isinstance(ip, ipaddress.IPv4Address):
            subnets.append(ipaddress.IPv4Network(f"{ip}/32", strict=False))
        else:  # IPv6
            subnets.append(ipaddress.IPv6Network(f"{ip}/128", strict=False))
    
    # If we have too many subnets, we need to consolidate
    if len(subnets) > max_subnets:
        # Keep merging adjacent subnets until we're under the limit
        while len(subnets) > max_subnets:
            merged = False
            i = 0
            
            while i < len(subnets) - 1:
                subnet1 = subnets[i]
                subnet2 = subnets[i + 1]
                
                # Check if they can be merged (same version)
                if type(subnet1) == type(subnet2):
                    # Find the smallest supernet that contains both
                    prefixlen = min(subnet1.prefixlen, subnet2.prefixlen)
                    while prefixlen >= 0:
                        supernet1 = subnet1.supernet(new_prefix=prefixlen)
                        # Correct way to check if subnet2 is contained in supernet1
                        if subnet2.subnet_of(supernet1):
                            # Merge and replace the two subnets with the supernet
                            subnets[i] = supernet1
                            subnets.pop(i + 1)
                            merged = True
                            break
                        prefixlen -= 1
                
                if merged:
                    break
                i += 1
                
            # If we can't merge any more, but still have too many subnets,
            # we'll have to be more aggressive with merging
            if not merged and len(subnets) > max_subnets:
                # Group by IP version
                ipv4_subnets = [s for s in subnets if isinstance(s, ipaddress.IPv4Network)]
                ipv6_subnets = [s for s in subnets if isinstance(s, ipaddress.IPv6Network)]
                
                # For each version, merge the smallest subnets first
                if ipv4_subnets:
                    ipv4_subnets.sort(key=lambda x: x.prefixlen, reverse=True)
                    for i in range(len(ipv4_subnets) - 1):
                        if len(subnets) <= max_subnets:
                            break
                        subnet1 = ipv4_subnets[i]
                        subnet2 = ipv4_subnets[i + 1]
                        # Find common supernet with one bit less
                        supernet = subnet1.supernet(new_prefix=subnet1.prefixlen - 1)
                        # Correct check for subnet containment
                        if subnet2.subnet_of(supernet):
                            # Replace with supernet
                            subnets.remove(subnet1)
                            subnets.remove(subnet2)
                            subnets.append(supernet)
                
                if ipv6_subnets and len(subnets) > max_subnets:
                    ipv6_subnets.sort(key=lambda x: x.prefixlen, reverse=True)
                    for i in range(len(ipv6_subnets) - 1):
                        if len(subnets) <= max_subnets:
                            break
                        subnet1 = ipv6_subnets[i]
                        subnet2 = ipv6_subnets[i + 1]
                        # Find common supernet with one bit less
                        supernet = subnet1.supernet(new_prefix=subnet1.prefixlen - 1)
                        # Correct check for subnet containment
                        if subnet2.subnet_of(supernet):
                            # Replace with supernet
                            subnets.remove(subnet1)
                            subnets.remove(subnet2)
                            subnets.append(supernet)
            
            # If we still can't get under the limit, force merge closest subnets
            if not merged and len(subnets) > max_subnets:
                # Sort by prefix length (smallest networks first)
                subnets.sort(key=lambda x: x.prefixlen, reverse=True)
                # Merge the two smallest networks
                if len(subnets) >= 2:
                    subnet1 = subnets[0]
                    subnet2 = subnets[1]
                    if type(subnet1) == type(subnet2):
                        # Find smallest common supernet
                        common_net = find_common_supernet(subnet1, subnet2)
                        if common_net:
                            subnets.remove(subnet1)
                            subnets.remove(subnet2)
                            subnets.append(common_net)
    
    # Convert networks back to CIDR strings
    return [str(subnet) for subnet in subnets]


def find_common_supernet(net1, net2):
    """Find the smallest common supernet for two networks."""
    if type(net1) != type(net2):
        return None
    
    # Start with smallest possible supernet
    prefixlen = min(net1.prefixlen, net2.prefixlen) - 1
    
    while prefixlen >= 0:
        try:
            # Try to find a supernet that contains both
            supernet1 = net1.supernet(new_prefix=prefixlen)
            # Correct check for subnet containment
            if net2.subnet_of(supernet1):
                return supernet1
        except ValueError:
            pass
        prefixlen -= 1
    
    return None

def write_samplicator_config_to_files(max_subnets):
    try:
        livenx_inventory = get_livenx_inventory()
        livenx_nodes = get_livenx_nodes()
        config_filename = "samplicator_config.conf"
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
        with open(config_filename, 'w') as config_file:
            for i, subnet in enumerate(subnets):
                node_ip = node_ips[i % len(node_ips)]  # Cycle through node IPs
                ip = str(ipaddress.ip_network(subnet)).split('/')[0]
                dotted_notation = str(ipaddress.ip_network(subnet).netmask)
                line = f"{ip}/{dotted_notation}: {node_ip}/2055\n"
                local_logger.debug(f"Writing line to config file: {line.strip()}")
                config_file.write(line)

        # check every device to see if the node ip it was previously assigned to has changed
        for device in livenx_inventory.get('devices', []):
            device_ip = device.get('address')
            if device_ip:
                # Check if the device IP is in the new subnets
                for subnet in subnets:
                    print(f'device_ip={device_ip}, subnet={subnet}')
                    if ipaddress.ip_address(device_ip) in ipaddress.ip_network(subnet):
                        # If it is, update the node IP for that device
                        node_ip = node_ips[subnets.index(subnet) % len(node_ips)]
                        local_logger.debug(f"Updating device {device['hostName']} to new node IP: {node_ip}")
                        device['nodeId'] = node_ip
                        break
    except Exception as err:
        local_logger.error(f"Error writing out samplicator config: {err}")

def add_test_devices(start_num, num_devices):
    try:
        livenx_inventory = {}
        livenx_devices = []
        nodes = get_livenx_nodes()
        
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
        
def main(args):
    ## trace input arguments
    local_logger.debug(args)

    if args.addtestdevices is not None and args.addtestdevices > 0:
        # Write outtest devices
        add_test_devices(args.addtestdevicesstartnum, args.addtestdevices)
        exit(1)

    if args.writesamplicatorconfig:
        # Write the samplicator config
        write_samplicator_config_to_files(args.writesamplicatorconfigmaxsubnets)
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
        new_device_inventory = None
        for i in range(0, len(ip_list), 10):  # Process in chunks of 10
            chunk = ip_list[i:i + 10]
            new_device_inventory = map_ip_to_livenx_inventory(chunk)
            # Add IP to LiveNX
            if isinstance(new_device_inventory, dict) and len(new_device_inventory.get('devices', [])) > 0:
                add_to_livenx_inventory(new_device_inventory)
            else:
                local_logger.info("No device to add")


import unittest
import ipaddress
from typing import List


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
    result = group_ips_into_subnets(["2001:db8::1"])
    assert result == ["2001:db8::1/128"], "IPv6 address should return single /128 subnet"
    
    # Test case 4: Mixed IPv4 and IPv6
    result = group_ips_into_subnets(["192.168.1.1", "2001:db8::1"])
    assert set(result) == {"192.168.1.1/32", "2001:db8::1/128"}, "Mixed IP versions should work"
    
    # Test case 5: Duplicate IPs
    result = group_ips_into_subnets(["192.168.1.1", "192.168.1.1", "192.168.1.1"])
    assert result == ["192.168.1.1/32"], "Duplicate IPs should be removed"
    
    # Test case 6: Sequential IPs that can be merged
    result = group_ips_into_subnets(["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"], max_subnets=1)
    print(result)
    assert result == ["192.168.1.0/30"], "Sequential IPs should merge into a single subnet"
    
    # Test case 7: IPs that cannot be perfectly merged
    result = group_ips_into_subnets(["192.168.1.1", "192.168.1.3", "192.168.1.5", "192.168.1.7"], max_subnets=1)
    assert result == ["192.168.1.0/29"], "Non-sequential IPs should merge into smallest containing subnet"
    
    # Test case 8: Force merge with max_subnets
    large_list = [f"192.168.{i}.{j}" for i in range(10) for j in range(10)]  # 100 IPs
    result = group_ips_into_subnets(large_list, max_subnets=5)
    assert len(result) <= 5, f"Result should have at most 5 subnets, got {len(result)}"
    
    # Test case 9: Invalid IPs
    result = group_ips_into_subnets(["192.168.1.1", "invalid_ip", "10.0.0.1"])
    assert set(result) == {"192.168.1.1/32", "10.0.0.1/32"}, "Invalid IPs should be ignored"
    
    # Test case 10: Different IP blocks
    result = group_ips_into_subnets(["10.0.0.1", "172.16.0.1", "192.168.1.1"], max_subnets=3)
    assert set(result) == {"10.0.0.1/32", "172.16.0.1/32", "192.168.1.1/32"}, "Different IP blocks should remain separate"
    
    # Test case 11: Max subnets larger than needed
    result = group_ips_into_subnets(["192.168.1.1", "192.168.1.2"], max_subnets=10)
    assert len(result) <= 10, "Should respect max_subnets even when not needed"
    
    # Test case 12: IPv6 merging
    ipv6_list = [f"2001:db8::{i}" for i in range(10)]
    result = group_ips_into_subnets(ipv6_list, max_subnets=1)
    assert len(result) == 1, "IPv6 addresses should merge correctly"
    
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
    parser = argparse.ArgumentParser(description="Process Auto add device to LiveNX from log file")
    parser.add_argument("--logfile", type=str, help="Add Log file")
    parser.add_argument('--writesamplicatorconfig', action="store_true", help='Write the samplicator config')
    parser.add_argument('--writesamplicatorconfigmaxsubnets', type=int, help='The maximum number of subnets to write out to the config file')
    parser.add_argument('--addtestdevices', type=int, help='Add a number of test devices starting at 10.x.x.x.')
    parser.add_argument('--addtestdevicesstartnum', type=int, help='The starting index number for the test devices at 10.x.x.x.')
    args = parser.parse_args()
    main(args)
