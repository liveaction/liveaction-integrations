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
    interface ={
        "ifIndex": if_index,
        "name": f"Interface{if_index}/0",
        "address": ip4,
        "wan": False,
        "xcon": False,
        "label": "",
        "stringTags": ""
    }
    payload = {
        "devices": [
            {
            "deviceSerial": f"{device_serial}",
            "interfaces": [{interface}]
            }
        ]
    }
    
    try:
        # Create the request and add the Content-Type header
        request, ctx = create_request(f"/v1/devices/virtual/interfaces", json.dumps(payload).encode('utf-8'))
        logging.info(payload)
        request.add_header("Content-Type", "application/json")
        request.add_header("accept", "application/json")
        # Specify the request method as POST
        request.method = "POST"
        
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
