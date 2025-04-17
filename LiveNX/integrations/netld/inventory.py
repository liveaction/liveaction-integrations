
#!/usr/bin/env python3

import os
from netld.jsonrpc import JsonRpcProxy
from common.livenx_inventory import get_livenx_nodes
import logging
local_logger = logging.getLogger(__name__)

thirdeyeHost = os.getenv("THIRDEYE_API_HOST")
thirdeyeUser = os.getenv("THIRDEYE_API_USER")
thirdeyePass = os.getenv("THIRDEYE_API_PASSWORD")
thirdeyeNetwork = os.getenv("THIRDEYE_NETWORK")
liveNxTargetIP = os.getenv("LIVENX_TARGET_IP")

def map_livenx_vendor_id_to_netld_adapter_vendor_id(vendor):
    if vendor == "Cisco":
        return 'Cisco::IOS'
    return 'Cisco::IOS'

def create_livenx_interface_from_netld_interface(address):
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

def create_livenx_device_from_netld_device(nodeid, netld_device):
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
    livenx_device['interfaces'] = create_livenx_interface_from_netld_interface(netld_device['ipAddress'])
    livenx_device['hostName'] = netld_device['hostname']
    livenx_device['systemName'] = netld_device['hostname']
    livenx_device['systemDescription'] = ''
    livenx_device['address'] = netld_device['ipAddress']
    livenx_device['site'] = thirdeyeNetwork
    #livenx_device['groupId'] = str(uuid.uuid4())
    #livenx_device['groupName'] = ""
    livenx_device['stringTags'] = ""
    livenx_device['userDefinedSampleRatio'] = 1
    local_logger.info(livenx_device)
    return livenx_device

def create_netld_device_from_livenx_device(livenx_device):
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
    netld_device = {}
    netld_device['hostname'] = livenx_device['hostName']
    netld_device['ipAddress'] = livenx_device['address']
    netld_device['network'] = thirdeyeNetwork
    vendorProduct = livenx_device.get('vendorProduct', None)
    vendorDisplayName = "Cisco"

    if vendorProduct != None:
        vendorDisplayName = livenx_device['vendorProduct']['displayName']


    netld_device['adapterId'] = map_livenx_vendor_id_to_netld_adapter_vendor_id(vendorDisplayName)
    netld_device['model'] = vendorDisplayName
    netld_device['softwareVendor'] = vendorDisplayName
    netld_device['osVersion'] = livenx_device.get('osVersionString', '')
    #netld_device['backupStatus'] = livenx_device['???']
    netld_device['serialNumber'] = livenx_device.get('serial', '')
    local_logger.info(netld_device)
    return netld_device


def map_livenx_inventory_to_netld_inventory(livenx_inventory):
    netld_inventory = []
    for livenx_device in livenx_inventory:
        netld_inventory.append(create_netld_device_from_livenx_device(livenx_device))
    return netld_inventory

def map_netld_inventory_to_livenx_inventory(netld_inventory):
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
    for netld_device in netld_inventory:
        livenx_devices.append(create_livenx_device_from_netld_device(nodeid, netld_device))
    
    livenx_inventory['devices'] = livenx_devices
    return livenx_inventory

def add_to_netld_inventory(netld_inventory):
    ### Create a JSON-RPC proxy for the inventory service
    ###
    _netld_svc = JsonRpcProxy.fromHost(thirdeyeHost, thirdeyeUser, thirdeyePass)

    for netld_device in netld_inventory:
        error = _netld_svc.call('Inventory.createDevice', 'Default', netld_device['ipAddress'], netld_device['adapterId'])

        if error != None:
            local_logger.info('Inventory.createDevice: ' + str(error))
        error = _netld_svc.call('Inventory.updateDevice', 'Default', netld_device['ipAddress'], None, None, None, netld_device['hostname'])
        if error != None:
            local_logger.info('Inventory.updateDevice: ' + str(error))
    ### Logout using the security service to be nice to the server
    ###
    _netld_svc.call('Security.logoutCurrentUser')

def remove_from_netld_inventory(netld_inventory):
    ### Create a JSON-RPC proxy for the inventory service
    ###
    _netld_svc = JsonRpcProxy.fromHost(thirdeyeHost, thirdeyeUser, thirdeyePass)

    for netld_device in netld_inventory:
        error = _netld_svc.call('Inventory.deleteDevice', 'Default', netld_device['ipAddress'])

        if error != None:
             local_logger.info('Inventory.deleteDevice: ' + str(error))
    ### Logout using the security service to be nice to the server
    ###
    _netld_svc.call('Security.logoutCurrentUser')

def get_netld_inventory():
    ### Create a JSON-RPC proxy for the inventory service
    ###
    devices = []
    _netld_svc = JsonRpcProxy.fromHost(thirdeyeHost, thirdeyeUser, thirdeyePass)

    # page data object for iterating ThirdEye inventory search results
    pageData = {'offset': 0, 'pageSize': 500}

    while True:
        pageData = _netld_svc.call('Inventory.search', [thirdeyeNetwork], 'ipAddress', "", pageData, 'ipAddress', False)

        if pageData['total'] == 0:
            break

        for device in pageData['devices']:
            local_logger.info(device)
            devices.append(device)

        # break if we've reached the end
        if pageData['offset'] + pageData['pageSize'] >= pageData['total']:
            break

        # next page
        pageData['offset'] += pageData['pageSize']


    ### Logout using the security service to be nice to the server
    ###
    _netld_svc.call('Security.logoutCurrentUser')
    return devices