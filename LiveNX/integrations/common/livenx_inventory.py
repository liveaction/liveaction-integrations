import ssl
import urllib.request, urllib.parse
import os
import json
import logging
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
  client = connect_with_tls(host=clickHouseHost, port=int(clickHouseApiPort), user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)

  # Define the query to retrieve all contents of the Device_Inventory table
  query = "SELECT Host_Name, Client_IP FROM Device_Inventory"

  try:
      # Execute the query
      results = client.execute(query)

      # Process and display results
      for result in results:
          formatted_result = dict(zip(["hostName", "clientIp"], result))
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

def diff_livenx_ch_inventory(livenx_inventory_1, livenx_inventory_2):
    livenx_inventory_diff_list = []

    for livenx_device_1 in livenx_inventory_1['devices']:
        livenx_device_found = False
        for livenx_device_2 in livenx_inventory_2['devices']:
            if compare_livenx_device(livenx_device_1, livenx_device_2):
                livenx_device_found = True
                break
        if livenx_device_found == False:
            livenx_inventory_diff_list.append(livenx_device_1)    
    return livenx_inventory_diff_list

def add_to_livenx_ch_inventory(livenx_inventory):

  # Connect to ClickHouse
  client = connect_with_tls(host=clickHouseHost, port=int(clickHouseApiPort), user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)

  # Prepare the INSERT statement
  insert_query = """
  INSERT INTO Device_Inventory (
      Href, ID, Serial, Client_IP, System_Name, Display_System_Name, Host_Name, Display_Host_Name, 
      System_Location, System_Description, OS_Version.Major_Number, OS_Version.Minor_Number,
      OS_Version.OS_Type, OS_Version_String, Vendor_Product.Model, Vendor_Product.Vendor,
      Site, Is_Data_Center_Site, Tags, Tagged_Omni
  ) VALUES
  """
  clickhouse_data = []
  for data in livenx_inventory:
    values = (
        data.get("href",""), data.get("id",""), data.get("serial",""), data.get("clientIp",""), data.get("systemName",""), 
        data.get("displaySystemName",""), data.get("hostName",""), data.get("displayHostName",""), data.get("systemLocation",""), 
        data.get("systemDescription",""), (data.get("osVersion",{}).get("majorNumber",""),), (data.get("osVersion",{}).get("minorNumber",""),),
        (data.get("osVersion",{}).get("osType",""),), data.get("osVersionString",""), (data.get("vendorProduct",{}).get("model",""),),
        ([[(data.get("vendorProduct",{}).get("vendor",{}).get("vendorName",""),data.get("vendorProduct",{}).get("vendor",{}).get("vendorOid",{}).get("displayName",''),data.get("vendorProduct",{}).get("vendor",{}).get("vendorSerialOid",{}).get("displayName",''))]]),
        data.get("site",""), data.get("isDataCenterSite",""), data.get("tags",""), data.get("taggedOmni","")
    )
    clickhouse_data.append(values)

  try:
      # Execute the INSERT statement
      client.execute(insert_query, clickhouse_data)
      local_logger.info("Data inserted successfully.")
      print("Data inserted successfully.")
  except Exception as e:
      local_logger.error(f"Error inserting data: {e}")
      print(f"Error inserting data: {e}")

def remove_from_livenx_ch_inventory(livenx_inventory):
    # Connect to ClickHouse
    client = connect_with_tls(host=clickHouseHost, port=int(clickHouseApiPort), user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)

    # Prepare the DELETE statement template
    delete_query = """
    ALTER TABLE Device_Inventory DELETE WHERE ID = %s
    """

    for data in livenx_inventory['devices']:
        try:
            # Use the ID from each device to identify and remove the entry
            device_id = data["id"]
            
            # Execute the DELETE statement
            client.execute(delete_query, (device_id,))
            local_logger.info(f"Device with ID {device_id} removed successfully.")
            print(f"Device with ID {device_id} removed successfully.")
        except Exception as e:
            local_logger.error(f"Device with ID {device_id} removed successfully.")
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