import json
import urllib.request
import json
import ssl
import os
import logging

liveNxApiHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN")

if not liveNxApiHost or not liveNxApiPort or not liveNxApiToken:
    raise EnvironmentError("Environment variables LIVENX_API_HOST, LIVENX_API_PORT, and LIVENX_API_TOKEN must be set.")


def set_interfaces(device_serial: str, ifIndexes: list[int], ip4: str):
    """ HTTP PUT JSON FORMAT
    {
  "devices": [
    {
      "deviceSerial": "John's Device",
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
}"""
    interfaces = []
    payload = {}
    for if_index in ifIndexes:
        interface = {
            "ifIndex": f"{if_index}",
            "name": f"Interface{if_index}/0",
            "address": ip4,
            "subnetMask": "255.255.255.0",
            "description": "",
            "serviceProvider": "",
            "inputCapacity": "1000000",
            "outputCapacity": "1000000",
            "wan": True,
            "xcon": False,
            "label": f"Interface{if_index}/0",
            "stringTags": "",
            }
        interfaces.append(interface)

    payload = {
        "devices": [
            {
            "deviceSerial": f"{device_serial}",
            "interfaces": interfaces
            }
        ]
    }
  
    j = json.dumps(payload).encode('utf-8')
    try:
        # Create the request and add the Content-Type header
        request, ctx = create_request(f"/v1/devices/virtual/interfaces", j)
        logging.info(payload)
        request.add_header("Content-Type", "application/json")
        request.add_header("accept", "application/json")
        # Specify the request method as PUT
        request.method = "PUT"
        
        with urllib.request.urlopen(request, context=ctx) as response:
            response_data = response.read().decode('utf-8')
            logging.debug(response_data)
    except Exception as err:
        logging.error(f"Error on /v1/devices/virtual/interfaces API Call {err}")

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

def get_livenx_inventory():

    api_url = "/v1/devices?includeHistorical=false"

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


def get_livenx_nodes(include_server: bool = False):
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
                  # Check if the node is local, if it is the server, or if include_server is True
                  if include_server or (node.get('local', False) == False):
                      if node.get('ipAddress') == 'Local':
                          # If the node is local, set the IP address to the host
                          node['ipAddress'] = liveNxApiHost
                      ret_nodes.append(node)
              return ret_nodes
          else:
              # Handle the case where 'nodes' doesn't exist
              return []
    except Exception as err:
        logging.error(f"Error while call /v1/nodes: {err}")
    
    return []

def get_livenx_node_id_from_ip(nodes, ip: str):
    """
    Get the node id from the ip address
    """
    try:
        for node in nodes:
            if node['ipAddress'] == ip:
                return node['id']
    except Exception as err:
        logging.error(f"Error while getting IP: {err}")
    
    return None