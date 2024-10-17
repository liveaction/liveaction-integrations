import ssl
import urllib.request, urllib.parse
import os
import json
import logging
local_logger = logging.getLogger(__name__)


liveNxHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxToken = os.getenv("LIVENX_API_TOKEN")
liveNxTargetIP = os.getenv("LIVENX_TARGET_IP")
thirdEyeHost = os.getenv("THIRDEYE_API_HOST")

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
    is_same = livenx_device_1['hostName'] == livenx_device_2['hostName'] and livenx_device_1['address'] == livenx_device_2['address']
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