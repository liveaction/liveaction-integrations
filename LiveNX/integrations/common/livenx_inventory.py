import ssl
import urllib.request, urllib.parse
import os
import json
import logging
import requests
from helper.clickhouse import connect_with_tls

local_logger = logging.getLogger(__name__)


liveNxHost = os.getenv("LIVENX_API_HOST","")
liveNxApiPort = os.getenv("LIVENX_API_PORT","")
liveNxToken = os.getenv("LIVENX_API_TOKEN","")
liveNxTargetIP = os.getenv("LIVENX_TARGET_IP","")
thirdEyeHost = os.getenv("THIRDEYE_API_HOST","")
clickHouseHost = os.getenv("CLICKHOUSE_HOST","")
clickHouseUsername = os.getenv("CLICKHOUSE_USERNAME","")
clickHousePassword = os.getenv("CLICKHOUSE_PASSWORD","")
clickHouseApiPort = os.getenv("CLICKHOUSE_PORT","")
clickhouseCACerts = os.getenv("CLICKHOUSE_CACERTS", "/path/to/ca.pem")
clickhouseCertfile = os.getenv("CLICKHOUSE_CERTFILE", "/etc/clickhouse-server/cacerts/ca.crt")
clickhouseKeyfile = os.getenv("CLICKHOUSE_KEYFILE", "/etc/clickhouse-server/cacerts/ca.key")
bluecatHost = os.getenv("BLUECAT_API_HOST")
bluecatUser = os.getenv("BLUECAT_API_USER")
bluecatPass = os.getenv("BLUECAT_API_PASSWORD")


THIRD_EYE_URL = "https://" + thirdEyeHost

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

def compare_livenx_device(livenx_device_1, livenx_device_2):
    is_same = livenx_device_1['hostName'] == livenx_device_2['hostName'] and (livenx_device_1.get('address','') == livenx_device_2.get('address','') or livenx_device_1.get('clientIp','') == livenx_device_2.get('clientIp',''))
    return is_same

def diff_livenx_inventory(livenx_inventory_1, livenx_inventory_2):
    livenx_inventory_diff_list = []

    for livenx_device_1 in livenx_inventory_1['devices']:
        livenx_device_found = False
        for livenx_device_2 in livenx_inventory_2['devices']:
            if compare_livenx_device(livenx_device_1, livenx_device_2):
                livenx_device_found = True
                break
        if livenx_device_found == False:
            description = livenx_device_1.get('systemDescription')
            livenx_device_1['systemDescription'] = description+ f'\n Click to LogicView Redirect {THIRD_EYE_URL}' if description else THIRD_EYE_URL
            livenx_inventory_diff_list.append(livenx_device_1)    
    return livenx_inventory_diff_list

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

def get_livenx_ch_inventory():

  # Connect to ClickHouse
  livenx_ch_inventory = []
  client = connect_with_tls(host=clickHouseHost, port=clickHouseApiPort, user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)

  # Define the query to retrieve all contents of the Device_Inventory table
  query = "SELECT ID, Host_Name, Client_IP, Serial FROM Device_Inventory"

  try:
      # Execute the query
      results = client.execute(query)

      # Process and display results
      for result in results:
          formatted_result = dict(zip(["id", "hostName", "clientIp", "serial"], result))
          livenx_ch_inventory.append(formatted_result)

  except Exception as e:
      local_logger.error(f"An error occurred while querying ClickHouse: {e}")
      print(f"An error occurred while querying ClickHouse: {e}")
  finally:
      client.disconnect()
  return {"devices": livenx_ch_inventory}
  


def create_livenx_ch_device_from_livenx_device(livenx_device):
    '''
    
    {
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
}
    
    '''
    return livenx_device

def map_livenx_inventory_to_livenx_ch_inventory(livenx_inventory):
    livenx_ch_inventory = {}
    livenx_devices = []
    for livenx_device in livenx_inventory:
        livenx_devices.append(create_livenx_ch_device_from_livenx_device(livenx_device))
    
    livenx_ch_inventory['devices'] = livenx_devices
    return livenx_inventory

def compare_livenx_ch_device(livenx_device_1, livenx_device_2):
    is_same = livenx_device_1['serial'] == livenx_device_2['serial']
    return is_same

def diff_livenx_ch_inventory(livenx_inventory_1, livenx_inventory_2):
    livenx_inventory_diff_list = []

    for livenx_device_1 in livenx_inventory_1['devices']:
        livenx_device_found = False
        for livenx_device_2 in livenx_inventory_2['devices']:
            if compare_livenx_ch_device(livenx_device_1, livenx_device_2):
                livenx_device_found = True
                break
        if livenx_device_found == False:
            if 'id' in livenx_device_1:
                livenx_inventory_diff_list.append(livenx_device_1)
            else:
                livenx_inventory_diff_list.append(livenx_device_2)
              
    return livenx_inventory_diff_list

def add_to_livenx_ch_inventory(livenx_inventory):

  # Connect to ClickHouse
  client = connect_with_tls(host=clickHouseHost, port=clickHouseApiPort, user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)

  for data in livenx_inventory:
    columns = []
    values = []

    # check for href
    if data.get('href'):
      columns.append("Href")
      values.append(data.get("href"))
    if data.get('id'):
      columns.append("ID")
      values.append(str(data.get("id")))
    if data.get('serial'):
      columns.append("Serial")
      values.append(data.get("serial"))
    if data.get('clientIp'):
      columns.append("Client_IP")
      values.append(data.get("clientIp"))
    if data.get('systemName'):
      columns.append("System_Name")
      values.append(data.get("systemName"))
    if data.get('displaySystemName'):
      columns.append("Display_System_Name")
      values.append(data.get("displaySystemName"))
    if data.get('hostName'):
      columns.append("Host_Name")
      values.append(data.get("hostName"))
    if data.get('displayHostName'):
      columns.append("Display_Host_Name")
      values.append(data.get("displayHostName"))
    if data.get('systemLocation'):
      columns.append("System_Location")
      values.append(data.get("systemLocation"))
    if data.get('systemDescription'):
      columns.append("System_Description")
      values.append(data.get("systemDescription"))
    if data.get('osVersion',{}).get("majorNumber"):
      columns.append("OS_Version.Major_Number")
      values.append((data.get('osVersion',{}).get("majorNumber"),))
    if data.get('osVersion',{}).get("minorNumber"):
      columns.append("OS_Version.Minor_Number")
      values.append((data.get('osVersion',{}).get("minorNumber"),))
    if data.get('osVersion',{}).get("osType"):
      columns.append("OS_Version.OS_Type")
      values.append((data.get('osVersion',{}).get("osType"),))
    if data.get('osVersionString'):
      columns.append("OS_Version_String")
      values.append(data.get("osVersionString"))
    if data.get("vendorProduct",{}).get("model"):
      columns.append("Vendor_Product.Model")
      values.append((data.get("vendorProduct",{}).get("model"),))
    if data.get("vendorProduct",{}).get("vendor"):
      columns.append("Vendor_Product.Vendor")
      vendor = data.get("vendorProduct",{}).get("vendor",{})
      values.append([[(vendor.get("vendorName",""),vendor.get("vendorOid",{}).get("displayName",''),vendor.get("vendorSerialOid",{}).get("displayName",''))]])
    if data.get('site'):
      columns.append("Site")
      values.append(data.get("site"))
    if data.get('isDataCenterSite'):
      columns.append("Is_Data_Center_Site")
      values.append(data.get("isDataCenterSite"))
    if data.get('tags'):
      columns.append("Tags")
      values.append(data.get("tags"))
    if data.get('taggedOmni'):
      columns.append("Tagged_Omni")
      values.append(data.get("taggedOmni"))
    if data.get('type'):
      columns.append("Type")
      values.append(data.get("type"))
    if data.get('name'):
      columns.append("Name")
      values.append(data.get("name"))
    if data.get('configuration'):
      configuration = data.get("configuration",{})
      columns.append("Configuration.ID")
      values.append((str(configuration.get("id")),))
      columns.append("Configuration.Type")
      values.append((configuration.get("type"),))
      columns.append("Configuration.Name")
      values.append((configuration.get("name"),))
    if data.get('address'):
      columns.append("Client_IP")
      values.append(data.get("address"))
    if data.get('state'):
      columns.append("State")
      values.append(data.get("state"))
    if data.get('macAddress'):
      macAddress = data.get("macAddress",{})
      columns.append("MAC_Address.ID")
      values.append((str(macAddress.get("id")),))
      columns.append("MAC_Address.Type")
      values.append((macAddress.get("type"),))
      if macAddress.get("name") is not None:
        columns.append("MAC_Address.Name")
        values.append((macAddress.get("name",''),))
      columns.append("MAC_Address.Address")
      values.append((macAddress.get("address"),))
    if data.get('template'):
      template = data.get("template",{})
      columns.append("Template.ID")
      values.append((str(template.get("id")),))
      columns.append("Template.Type")
      values.append((template.get("type"),))
      columns.append("Template.Name")
      values.append((template.get("name"),))
    if data.get('location'):
      location = data.get("location",{})
      columns.append("Location.ID")
      values.append((str(location.get("id")),))
      columns.append("Location.Type")
      values.append((location.get("type"),))
      columns.append("Location.Name")
      values.append((location.get("name"),))
    if data.get('clientIdentifier'):
      clientIdentifier = data.get("clientIdentifier",{})
      columns.append("Client_Identifier.ID")
      values.append((str(clientIdentifier.get("id")),))
      columns.append("Client_Identifier.Type")
      values.append((clientIdentifier.get("type"),))
      columns.append("Client_Identifier.Name")
      values.append((clientIdentifier.get("name"),))
    if data.get('device'):
      device = data.get("device",{})
      columns.append("Device.ID")
      values.append((str(device.get("id")),))
      columns.append("Device.Type")
      values.append((device.get("type"),))
      columns.append("Device.Name")
      values.append((device.get("name"),))
    if data.get('leaseDateTime'):
      columns.append("Lease_Date_Time")
      values.append(data.get("leaseDateTime"))
    if data.get('leaseExpirationDateTime'):
      columns.append("Lease_Expiration_Date_Time")
      values.append(data.get("leaseExpirationDateTime"))
    if data.get('circuitId'):
      columns.append("Circuit_ID")
      values.append(data.get("circuitId"))
    if data.get('remoteId'):
      columns.append("Remote_ID")
      values.append(data.get("remoteId"))
    if len(data.get('parameterRequestList',[])) > 0:
      columns.append("Parameter_Request_List")
      values.append(data.get("parameterRequestList"))
    if data.get('vendorClassIdentifier'):
      columns.append("Vendor_Class_Identifier")
      values.append(data.get("vendorClassIdentifier"))
    if data.get('routerPortInfo'):
      columns.append("Router_Port_Info")
      values.append(data.get("routerPortInfo"))
    if data.get('switchPortInfo'):
      columns.append("Switch_Port_Info")
      values.append(data.get("switchPortInfo"))
    if data.get('vlanInfo'):
      columns.append("VLAN_Info")
      values.append(data.get("vlanInfo"))
    if data.get('ipGroup'):
      ipGroup = data.get("ipGroup",{})
      columns.append("IP_Group.ID")
      values.append((str(ipGroup.get("id")),))
      columns.append("IP_Group.Type")
      values.append((ipGroup.get("type"),))
      columns.append("IP_Group.Name")
      values.append((ipGroup.get("name"),))
    if data.get('userDefinedFields'):      
      keys = []
      values = []
      for k,v in data.get('userDefinedFields').items():
        keys.append(k)
        values.append(v)
      columns.append("User_Defined_Fields.Key") 
      values.append(tuple(keys))
      columns.append("User_Defined_Fields.Value")
      values.append(tuple(values))
    #Prepare insert query
    insert_query = f"INSERT INTO Device_Inventory ({','.join(columns)}) VALUES"
    try:
        # Execute the INSERT statement
        client.execute(insert_query, [tuple(values)])
        local_logger.info(f"Data inserted successfully for ID: {data.get('id')}")
    except Exception as e:
        local_logger.error(f"Error in ID: {data.get('id')} inserting data: {e}")

def remove_from_livenx_ch_inventory(livenx_inventory):
    # Connect to ClickHouse
    client = connect_with_tls(host=clickHouseHost, port=clickHouseApiPort, user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)

    # Prepare the DELETE statement template
    delete_query = "ALTER TABLE Device_Inventory DELETE WHERE ID = %(device_id)s"

    for data in livenx_inventory:
        try:
            # Use the ID from each device to identify and remove the entry
            device_id = data["id"]
            
            # Execute the DELETE statement
            client.execute(delete_query, {'device_id': device_id})
            local_logger.info(f"Device with ID {device_id} removed successfully.")
            print(f"Device with ID {device_id} removed successfully.")
        except Exception as e:
            local_logger.error(f"Error removing device with ID {device_id}: {e}")
            print(f"Error removing device with ID {data['id']}: {e}")

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


def remove_from_livenx_inventory(livenx_inventory):
    pass

def compare_bluecat_addresses(address_1, address_2):
    is_same = str(address_1['id']) == str(address_2['id'])
    return is_same

def diff_bluecat_addresses(addresses_1, addresses_2):
    addresses_diff_list = []

    for address_1 in addresses_1.get('devices', []):
        # print("====address_1", address_1)
        livenx_site_found = False
        for address_2 in addresses_2.get('devices', []):
            # print("====address_2", address_2)
            if compare_bluecat_addresses(address_1, address_2):
                livenx_site_found = True
                break
        if livenx_site_found == False:
            addresses_diff_list.append(address_1)    
    return addresses_diff_list

def get_bluecat_addresses():
    """
    {
        "count": 1,
        "data": [        
            {
                "id": 100915,
                "type": "IPv4Address",
                "name": null,
                "configuration": {
                    "id": 100883,
                    "type": "Configuration",
                    "name": "LiveAction",
                    "_links": {
                        "self": {
                            "href": "/api/v2/configurations/100883"
                        }
                    }
                },
                "address": "10.4.205.206",
                "state": "STATIC",
                "macAddress": {
                    "id": 100927,
                    "type": "MACAddress",
                    "name": null,
                    "address": "4C-D9-8F-93-86-E3",
                    "_links": {
                        "self": {
                            "href": "/api/v2/macAddresses/100927"
                        }
                    }
                },
                "template": null,
                "location": {
                    "id": 91645,
                    "type": "Location",
                    "name": "Milpitas",
                    "_links": {
                        "self": {
                            "href": "/api/v2/locations/91645"
                        }
                    }
                },
                "clientIdentifier": null,
                "device": {
                    "id": 100921,
                    "type": "Device",
                    "name": "FlowGenerator1",
                    "_links": {
                        "self": {
                            "href": "/api/v2/devices/100921"
                        }
                    }
                },
                "leaseDateTime": null,
                "leaseExpirationDateTime": null,
                "circuitId": null,
                "remoteId": null,
                "parameterRequestList": [],
                "vendorClassIdentifier": null,
                "routerPortInfo": null,
                "switchPortInfo": null,
                "vlanInfo": null,
                "ipGroup": null,
                "userDefinedFields": null,
                "_links": {
                    "self": {
                        "href": "/api/v2/addresses/100915"
                    },
                    "collection": {
                        "href": "/api/v2/networks/100913/addresses"
                    },
                    "up": {
                        "href": "/api/v2/networks/100913"
                    },
                    "leases": {
                        "href": "/api/v2/addresses/100915/leases"
                    },
                    "resourceRecords": {
                        "href": "/api/v2/addresses/100915/resourceRecords"
                    },
                    "deploymentOptions": {
                        "href": "/api/v2/addresses/100915/deploymentOptions"
                    },
                    "moves": {
                        "href": "/api/v2/addresses/100915/moves"
                    },
                    "templateApplications": {
                        "href": "/api/v2/addresses/100915/templateApplications"
                    },
                    "workflowRequests": {
                        "href": "/api/v2/addresses/100915/workflowRequests"
                    },
                    "tags": {
                        "href": "/api/v2/addresses/100915/tags"
                    },
                    "accessRights": {
                        "href": "/api/v2/addresses/100915/accessRights"
                    },
                    "transactions": {
                        "href": "/api/v2/addresses/100915/transactions"
                    },
                    "userDefinedLinks": {
                        "href": "/api/v2/addresses/100915/userDefinedLinks"
                    }
                }
            }
        ]
    }
    """
    if not (bluecatHost and bluecatUser and bluecatPass):
        raise Exception("Missing Bluecat Env setup")
    try:
        session_api_url = "/api/v2/sessions"
        session_api_url = f"https://{bluecatHost}{session_api_url}"

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        response = requests.post(session_api_url, data=json.dumps({
            "username": bluecatUser,
            "password": bluecatPass
        }), headers=headers, verify=False)
        
        # Process the JSON response
        session_response = response.json()
        apiToken = session_response.get('basicAuthenticationCredentials')
        # check token exist in response or not
        if apiToken:
            api_url = "/api/v2/addresses"

            api_url = f"https://{bluecatHost}{api_url}"

            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': f'Basic {apiToken}'
            }
            response = requests.get(api_url, headers=headers, verify=False)
            
            # Process the JSON response
            addresses = response.json()    
            return {'devices': addresses.get('data', [])}
        return []
    except Exception as err:
        local_logger.error(f"Error getting bluecat addresses: {err}")
        return []