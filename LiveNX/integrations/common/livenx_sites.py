import ssl
import urllib.request, urllib.parse
import os
import json
import logging
import requests

local_logger = logging.getLogger(__name__)


liveNxHost = os.getenv("LIVENX_API_HOST","")
liveNxApiPort = os.getenv("LIVENX_API_PORT","")
liveNxToken = os.getenv("LIVENX_API_TOKEN","")

bluecatHost = os.getenv("BLUECAT_API_HOST")
bluecatUser = os.getenv("BLUECAT_API_USER")
bluecatPass = os.getenv("BLUECAT_API_PASSWORD")

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

def compare_livenx_device(livenx_site_1, livenx_site_2):
    is_same = livenx_site_1['siteName'] == livenx_site_2['siteName']
    return is_same

def get_livenx_sites():

    api_url = "/v1/sites"

    request, ctx = create_request(api_url)
    request.add_header("Content-Type", "application/json")
    request.add_header("accept", "application/json")
    
    # Specify the request method as POST
    request.method = "GET"

    sites_data = []
    with urllib.request.urlopen(request, context=ctx) as response:
        response_data = response.read().decode('utf-8')
        # Parse the JSON response
        json_data = json.loads(response_data)
        for site in json_data.get('sites', []):
            sites_data.append(site)
    
    return {"sites":sites_data}
  


def create_livenx_sites_device_from_bluecat_blocks(bluecat_block):
    '''
    {
        "id": 100911,
        "type": "IPv4Block",
        "name": "FlowGeneratorLab",
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
        "range": "10.4.205.0/24",
        "template": null,
        "location": {
            "id": 91645,
            "type": "Location",
            "name": "Milpitas", --> Sites
            "_links": {
                "self": {
                    "href": "/api/v2/locations/91645"
                }
            }
        },
        "duplicateHostnamesAllowed": true,
        "pingBeforeAssignmentEnabled": false,
        "defaultView": null,
        "defaultZonesInherited": true,
        "restrictedZonesInherited": true,
        "lowWaterMark": 0,
        "highWaterMark": 100,
        "usagePercentage": {
            "addressAllocation": {
                "assigned": 1,
                "unassigned": 99
            },
            "networkAllocation": {
                "assigned": 100,
                "unassigned": 0
            }
        },
        "reverseZoneSigned": false,
        "reverseZoneSigningPolicy": null,
        "userDefinedFields": null,
        "_inheritedFields": [
            "lowWaterMark",
            "highWaterMark"
        ],
        "_links": {
            "self": {
                "href": "/api/v2/blocks/100911"
            },
            "collection": {
                "href": "/api/v2/configurations/100883/blocks"
            },
            "up": {
                "href": "/api/v2/configurations/100883"
            },
            "blocks": {
                "href": "/api/v2/blocks/100911/blocks"
            },
            "defaultZones": {
                "href": "/api/v2/blocks/100911/defaultZones"
            },
            "deploymentOptions": {
                "href": "/api/v2/blocks/100911/deploymentOptions"
            },
            "deploymentRoles": {
                "href": "/api/v2/blocks/100911/deploymentRoles"
            },
            "imports": {
                "href": "/api/v2/blocks/100911/imports"
            },
            "leases": {
                "href": "/api/v2/blocks/100911/leases"
            },
            "merges": {
                "href": "/api/v2/blocks/100911/merges"
            },
            "moves": {
                "href": "/api/v2/blocks/100911/moves"
            },
            "networks": {
                "href": "/api/v2/blocks/100911/networks"
            },
            "reconciliationPolicies": {
                "href": "/api/v2/blocks/100911/reconciliationPolicies"
            },
            "restrictedZones": {
                "href": "/api/v2/blocks/100911/restrictedZones"
            },
            "signingKeys": {
                "href": "/api/v2/blocks/100911/signingKeys"
            },
            "splits": {
                "href": "/api/v2/blocks/100911/splits"
            },
            "templateApplications": {
                "href": "/api/v2/blocks/100911/templateApplications"
            },
            "workflowRequests": {
                "href": "/api/v2/blocks/100911/workflowRequests"
            },
            "tags": {
                "href": "/api/v2/blocks/100911/tags"
            },
            "accessRights": {
                "href": "/api/v2/blocks/100911/accessRights"
            },
            "transactions": {
                "href": "/api/v2/blocks/100911/transactions"
            },
            "userDefinedLinks": {
                "href": "/api/v2/blocks/100911/userDefinedLinks"
            }
        }
    }
    
    '''
    location = bluecat_block.get('location')
    if location is not None:
      return {
          "siteName": location.get('name',''),
          "siteDescription": location.get('name',''),
          "type": location.get('type',''),
          "siteIpRanges":[bluecat_block.get('range','')]
        }
    return {}

def map_bluecat_blocks_to_livenx_sites(bluecat_blocks):
    livenx_sites = []
    for bluecat_block in bluecat_blocks:
        map_livenx_site = create_livenx_sites_device_from_bluecat_blocks(bluecat_block)
        if map_livenx_site:
          livenx_sites.append(map_livenx_site)
    
    return {'sites': livenx_sites}

def diff_bluecat_sites(livenx_sites_1, livenx_sites_2):
    livenx_sites_diff_list = []

    for livenx_site_1 in livenx_sites_1['sites']:
        livenx_site_found = False
        for livenx_site_2 in livenx_sites_2['sites']:
            if compare_livenx_device(livenx_site_1, livenx_site_2):
                livenx_site_found = True
                break
        if livenx_site_found == False:
            livenx_sites_diff_list.append(livenx_site_1)    
    return livenx_sites_diff_list

def get_bluecat_blocks():
    """
    {
        "count": 3,
        "data": [
            {
                "id": 100884,
                "type": "IPv6Block",
                "name": "Global Unicast Address Space",
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
                "range": "2000::/3",
                "location": null,
                "_inheritedFields": [],
                "userDefinedFields": null,
                "_links": {
                    "self": {
                        "href": "/api/v2/blocks/100884"
                    },
                    "collection": {
                        "href": "/api/v2/configurations/100883/blocks"
                    },
                    "up": {
                        "href": "/api/v2/configurations/100883"
                    },
                    "blocks": {
                        "href": "/api/v2/blocks/100884/blocks"
                    },
                    "networks": {
                        "href": "/api/v2/blocks/100884/networks"
                    },
                    "deploymentOptions": {
                        "href": "/api/v2/blocks/100884/deploymentOptions"
                    },
                    "deploymentRoles": {
                        "href": "/api/v2/blocks/100884/deploymentRoles"
                    },
                    "leases": {
                        "href": "/api/v2/blocks/100884/leases"
                    },
                    "reconciliationPolicies": {
                        "href": "/api/v2/blocks/100884/reconciliationPolicies"
                    },
                    "moves": {
                        "href": "/api/v2/blocks/100884/moves"
                    },
                    "imports": {
                        "href": "/api/v2/blocks/100884/imports"
                    },
                    "tags": {
                        "href": "/api/v2/blocks/100884/tags"
                    },
                    "accessRights": {
                        "href": "/api/v2/blocks/100884/accessRights"
                    },
                    "transactions": {
                        "href": "/api/v2/blocks/100884/transactions"
                    },
                    "userDefinedLinks": {
                        "href": "/api/v2/blocks/100884/userDefinedLinks"
                    }
                }
            },
            {
                "id": 100885,
                "type": "IPv6Block",
                "name": "Unique Local Address Space",
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
                "range": "fc00::/6",
                "location": null,
                "_inheritedFields": [],
                "userDefinedFields": null,
                "_links": {
                    "self": {
                        "href": "/api/v2/blocks/100885"
                    },
                    "collection": {
                        "href": "/api/v2/configurations/100883/blocks"
                    },
                    "up": {
                        "href": "/api/v2/configurations/100883"
                    },
                    "blocks": {
                        "href": "/api/v2/blocks/100885/blocks"
                    },
                    "networks": {
                        "href": "/api/v2/blocks/100885/networks"
                    },
                    "deploymentOptions": {
                        "href": "/api/v2/blocks/100885/deploymentOptions"
                    },
                    "deploymentRoles": {
                        "href": "/api/v2/blocks/100885/deploymentRoles"
                    },
                    "leases": {
                        "href": "/api/v2/blocks/100885/leases"
                    },
                    "reconciliationPolicies": {
                        "href": "/api/v2/blocks/100885/reconciliationPolicies"
                    },
                    "moves": {
                        "href": "/api/v2/blocks/100885/moves"
                    },
                    "imports": {
                        "href": "/api/v2/blocks/100885/imports"
                    },
                    "tags": {
                        "href": "/api/v2/blocks/100885/tags"
                    },
                    "accessRights": {
                        "href": "/api/v2/blocks/100885/accessRights"
                    },
                    "transactions": {
                        "href": "/api/v2/blocks/100885/transactions"
                    },
                    "userDefinedLinks": {
                        "href": "/api/v2/blocks/100885/userDefinedLinks"
                    }
                }
            },
            {
                "id": 100911,
                "type": "IPv4Block",
                "name": "FlowGeneratorLab",
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
                "range": "10.4.205.0/24",
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
                "duplicateHostnamesAllowed": true,
                "pingBeforeAssignmentEnabled": false,
                "defaultView": null,
                "defaultZonesInherited": true,
                "restrictedZonesInherited": true,
                "lowWaterMark": 0,
                "highWaterMark": 100,
                "usagePercentage": {
                    "addressAllocation": {
                        "assigned": 1,
                        "unassigned": 99
                    },
                    "networkAllocation": {
                        "assigned": 100,
                        "unassigned": 0
                    }
                },
                "reverseZoneSigned": false,
                "reverseZoneSigningPolicy": null,
                "userDefinedFields": null,
                "_inheritedFields": [
                    "lowWaterMark",
                    "highWaterMark"
                ],
                "_links": {
                    "self": {
                        "href": "/api/v2/blocks/100911"
                    },
                    "collection": {
                        "href": "/api/v2/configurations/100883/blocks"
                    },
                    "up": {
                        "href": "/api/v2/configurations/100883"
                    },
                    "blocks": {
                        "href": "/api/v2/blocks/100911/blocks"
                    },
                    "defaultZones": {
                        "href": "/api/v2/blocks/100911/defaultZones"
                    },
                    "deploymentOptions": {
                        "href": "/api/v2/blocks/100911/deploymentOptions"
                    },
                    "deploymentRoles": {
                        "href": "/api/v2/blocks/100911/deploymentRoles"
                    },
                    "imports": {
                        "href": "/api/v2/blocks/100911/imports"
                    },
                    "leases": {
                        "href": "/api/v2/blocks/100911/leases"
                    },
                    "merges": {
                        "href": "/api/v2/blocks/100911/merges"
                    },
                    "moves": {
                        "href": "/api/v2/blocks/100911/moves"
                    },
                    "networks": {
                        "href": "/api/v2/blocks/100911/networks"
                    },
                    "reconciliationPolicies": {
                        "href": "/api/v2/blocks/100911/reconciliationPolicies"
                    },
                    "restrictedZones": {
                        "href": "/api/v2/blocks/100911/restrictedZones"
                    },
                    "signingKeys": {
                        "href": "/api/v2/blocks/100911/signingKeys"
                    },
                    "splits": {
                        "href": "/api/v2/blocks/100911/splits"
                    },
                    "templateApplications": {
                        "href": "/api/v2/blocks/100911/templateApplications"
                    },
                    "workflowRequests": {
                        "href": "/api/v2/blocks/100911/workflowRequests"
                    },
                    "tags": {
                        "href": "/api/v2/blocks/100911/tags"
                    },
                    "accessRights": {
                        "href": "/api/v2/blocks/100911/accessRights"
                    },
                    "transactions": {
                        "href": "/api/v2/blocks/100911/transactions"
                    },
                    "userDefinedLinks": {
                        "href": "/api/v2/blocks/100911/userDefinedLinks"
                    }
                }
            }
        ]
    }
    """
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
            api_url = "/api/v2/blocks"

            api_url = f"https://{bluecatHost}{api_url}"

            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': f'Basic {apiToken}'
            }
            response = requests.get(api_url, headers=headers, verify=False)
            
            # Process the JSON response
            blocks = response.json()    
            return blocks.get('data', [])
        return []
    except Exception as err:
        print(f"Error getting bluecat addresses: {err}")
        return []



def add_to_livenx_sites(livenx_sites):

    '''
    {
      "id": "45dc8e15-45ae-47ab-aa45-d6c944590fab",
      "siteName": "Palo Alto",
      "siteDescription": "Main Palo Alto server hub",
      "type": "building",
      "isDataCenter": false,
      "siteIpRanges": [
        "1.1.1.1",
        "8.8.1.0/24"
      ],
      "isConfigured": true,
      "mailingAddress": {
        "address1": "901 Campisi Way",
        "address2": "Suite 222",
        "city": "Campbell",
        "state": "CA",
        "zip": "95008",
        "country": "United States"
      },
      "position": {
        "latitude": 37.4224428,
        "longitude": -122.0842467
      },
      "region": {
        "id": "47ab45ae-45dc-8e15-aa45-d6c944590fab",
        "longName": "California",
        "shortName": "CA",
        "type": "STATE",
        "parent": "string"
      },
      "contactName": "John Doe",
      "phoneNumber": "(1) 888-123-4567",
      "email": "support@liveaction.com",
      "numberOfEmployees": 123,
      "tierCategoryId": "2919faf1-1dbe-42c3-9930-c2df9f5d1fe0",
      "devices": {
        "devices": [
          {
            "deviceSerial": "9IRVE649AQF",
            "deviceName": "device.test.com",
            "hostName": "device",
            "wan": true,
            "taggedOmni": false
          }
        ]
      },
      "businessHours": {
        "site": "Palo Alto",
        "id": "45dc8e15-45ae-47ab-aa45-d6c944590fab",
        "timeSettings": {
          "days": [
            "monday",
            "tuesday"
          ],
          "startTime": "08:00",
          "endTime": "17:00",
          "timeZone": {
            "displayValue": "Pacific Time (US and Canada); Tijuana",
            "rawValue": "US/Pacific-New"
          },
          "enableDst": true
        },
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
        }
      },
      "tags": [
        "string"
      ]
    }
  
    '''


    # Convert the device list to a JSON string and encode it to bytes
    for livenx_site in livenx_sites:
      data = json.dumps(livenx_site).encode('utf-8')

      # Create the request and add the Content-Type header
      request, ctx = create_request("/v1/sites", data)
      local_logger.info(data)
      request.add_header("Content-Type", "application/json")
      request.add_header("accept", "application/json")
      # Specify the request method as POST
      request.method = "POST"
      
      with urllib.request.urlopen(request, context=ctx) as response:
          response_data = response.read().decode('utf-8')
          local_logger.info(response_data)
          # print("===response_data", response_data)
