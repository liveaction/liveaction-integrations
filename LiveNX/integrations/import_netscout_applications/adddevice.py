import argparse
import logging
import re
import os
import ssl
import json
import urllib.request, urllib.parse
import time
import sys

local_logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

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
              return json_data['nodes']
          else:
              # Handle the case where 'nodes' doesn't exist
              return []
    except Exception as err:
        local_logger.error(f"Error while call /v1/nodes: {err}")
    
    return []


def get_custom_applications():

    api_url = "/v1/applications/custom?source=nx"

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

def create_custom_applications_from_ip(data):
    """
        {
          "rank": 0,
          "name": "string",
          "description": "string",
          "urls": [
            "string"
          ],
          "uris": [
            "string"
          ],
          "ipRanges": [
            "string"
          ],
          "portMap": {
            "protocols": [
              "string"
            ],
            "portRanges": [
              "string"
            ],
            "protocol": [
              "string"
            ]
          },
          "nbarIds": [
            0
          ],
          "dscpTypes": [
            0
          ]
        }
    """
    livenx_device = {
          "rank": 0,
          "name": data.get('Application Name'),
          "description": data.get('Display Name'),
          # "urls": [
          #   "string"
          # ],
          # "uris": [
          #   "string"
          # ],
          "ipRanges": [
            data.get('Address Type')
          ],
          "portMap": {
            "protocols": [
              data.get('Protocol')
            ],
            "portRanges": [
              data.get('Port Number')
            ],
            "protocol": [
              data.get('Protocol')
            ]
          },
          "nbarIds": [
            0
          ],
          "dscpTypes": [
            0
          ]
        }
    return livenx_device


def map_ip_to_custom_applications(raw_list):
    for k, data in raw_list.items():
        livenx_payload = create_custom_applications_from_ip(data)
        local_logger.info(f"livenx_payload {livenx_payload}")
        add_to_custom_applications(livenx_payload)

def readFile(filename=None, delimiter=";"):
    """
        Read file Method
        Parameter: filename    
    """
    if filename is None:
        local_logger.info("File name is missing")
        exit(1)
    raw_dict = {}
    try:
        # Read file and return
        columns_header = [
            'Application Name', 'Type', 'Version Information', 
            'Build ID','Classification', 'Protocol', 'Flag 1', 'Port Number', 
            'Flag 2', 'Service Type', 'Address Type','Application Instance Name', 
            'Additional Identifier', 'Display Name', 'Agent Type', 'Agent ID', 
            'Some Count', 'Protocol Group', 'Additional Field', 
            'Timestamp', 'Event Flags']
        with open(filename) as rf:
            for line in rf.readlines():
                row = line.strip()
                if row == "":
                    continue                
                row_list = row.split(delimiter)                
                row_data = dict(zip(columns_header, row_list))
                if row_data.get('Address Type', None) is None:
                    continue
                raw_dict[row_data.get('Application Name')]=row_data
        local_logger.info(f"List of IPs {raw_dict}")
        return raw_dict
    except Exception as err:
        local_logger.error(f"Error while reading raw file {err}")
        return {}

def add_to_custom_applications(payload):

    '''
    {
    'rank': 0, 
    'name': 'A_Citrix', 
    'description': 'null', 
    'ipRanges': ['IP'], 
    'portMap': {
      'protocols': ['TCP'], 
      'portRanges': ['51000'], 
      'protocol': ['TCP']
    }, 
    'nbarIds': [0], 
    'dscpTypes': [0]}
  
    '''

    try:
      # Convert the device list to a JSON string and encode it to bytes
      data = json.dumps(payload).encode('utf-8')

      # Create the request and add the Content-Type header
      request, ctx = create_request("/v1/applications/custom?source=nx", data)
      local_logger.info(data)
      request.add_header("Content-Type", "application/json")
      request.add_header("accept", "application/json")
      # Specify the request method as POST
      request.method = "POST"
      
      with urllib.request.urlopen(request, context=ctx) as response:
          response_data = response.read().decode('utf-8')
          local_logger.info(response_data)
    except Exception as err:
        local_logger.error(f"Error on /v1/applications/custom?source=nx API Call {err}")


def main(args):
    ## trace input arguments
    local_logger.info(args)

    if args.rawfile is None:
        local_logger.info("Missing raw file")
        exit(1)
    
    if liveNxHost is None or liveNxApiPort is None or liveNxToken is None or liveNxTargetIP is None:
        local_logger.info("Missing env any of parameters: [LIVENX_API_HOST, LIVENX_API_PORT, LIVENX_API_TOKEN, LIVENX_TARGET_IP] ")
        exit(1)

    delimiter = ";"
    if args.delimiter is not None:
      delimiter =  args.delimiter    
        
    ## Get list of IPs from log file  
    raw_dict = readFile(args.rawfile, delimiter)
    # Map IP to Linenx Inventory 
    orginal_custom_applications = get_custom_applications()
    local_logger.info(f"List of orginal_custom_applications: {orginal_custom_applications}")  
    for custom_applications in orginal_custom_applications.get('applications',[]):          
      try:
        del raw_dict[custom_applications['name']]
      except Exception as err:
          pass
    if len(raw_dict) < 1:
      local_logger.info("No IP to add")
    else:
      local_logger.info(f"List of IPs to add: {raw_dict}")   
      map_ip_to_custom_applications(raw_dict)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Auto add device to LiveNX from log file")
    parser.add_argument("--rawfile", type=str, help="Add Raw file")
    parser.add_argument("--delimiter", type=str, help="Add file delimiter default semi-colon(;)")
    # parser.add_argument('--continuous', action="store_true", help='Run it continuously')
    args = parser.parse_args()
    main(args)