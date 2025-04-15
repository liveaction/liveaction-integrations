import json
import urllib.request
import json
import ssl
import os
import logging

liveNxApiHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxApiToken = os.getenv("LIVENX_API_TOKEN")


def add_interface(device_serial: str, if_index: int, ip4: str):
    """ HTTP PUT JON FORMAT
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
}"""
    interface = {
        "ifIndex": f"{if_index}",
        "name": f"Interface{if_index}/0",
        "address": ip4,
        "subnetMask": "255.255.255.0",
        "description": f"Interface {if_index}",
        "serviceProvider": "",
        "inputCapacity": "1000000",
        "outputCapacity": "1000000",
        "wan": False,
        "xcon": False,
        "label": "",
        "stringTags": ""
    }
    print(interface)
    payload = {
        "devices": [
            {
            "deviceSerial": f"{device_serial}",
            "interfaces": f"[{interface}]"
            }
        ]
    }
   
    print(payload)
    try:
        # Create the request and add the Content-Type header
        request, ctx = create_request(f"/v1/devices/virtual/interfaces", json.dumps(payload).encode('utf-8'))
        logging.info(payload)
        request.add_header("Content-Type", "application/json")
        request.add_header("accept", "application/json")
        # Specify the request method as PUT
        request.method = "PUT"
        
        with urllib.request.urlopen(request, context=ctx) as response:
            response_data = response.read().decode('utf-8')
            logging.info(response_data)
    except Exception as err:
        logging.error(f"Error on /v1/devices/virtual/interface API Call {err}")

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
