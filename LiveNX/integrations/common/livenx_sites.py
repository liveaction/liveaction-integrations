import ssl
import urllib.request, urllib.parse
import os
import json
import logging
import requests
from helper.clickhouse import connect_with_tls
from utils.custom_uuid import is_valid_uuid

local_logger = logging.getLogger(__name__)


liveNxHost = os.getenv("LIVENX_API_HOST","")
liveNxApiPort = os.getenv("LIVENX_API_PORT","")
liveNxToken = os.getenv("LIVENX_API_TOKEN","")

bluecatHost = os.getenv("BLUECAT_API_HOST")
bluecatUser = os.getenv("BLUECAT_API_USER")
bluecatPass = os.getenv("BLUECAT_API_PASSWORD")

clickHouseHost = os.getenv("CLICKHOUSE_HOST","")
clickHouseUsername = os.getenv("CLICKHOUSE_USERNAME","")
clickHousePassword = os.getenv("CLICKHOUSE_PASSWORD","")
clickHouseApiPort = os.getenv("CLICKHOUSE_PORT","")
clickhouseCACerts = os.getenv("CLICKHOUSE_CACERTS", "/path/to/ca.pem")
clickhouseCertfile = os.getenv("CLICKHOUSE_CERTFILE", "/etc/clickhouse-server/cacerts/ca.crt")
clickhouseKeyfile = os.getenv("CLICKHOUSE_KEYFILE", "/etc/clickhouse-server/cacerts/ca.key")

def create_request(url, data = None):
    if not liveNxHost or not liveNxApiPort or not liveNxToken:
        raise Exception("Missing LiveNx Env setup")
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

def compare_livenx_site(livenx_site_1, livenx_site_2):
    is_same = str(livenx_site_1.get('id')) == str(livenx_site_2.get('id'))
    return is_same

def get_livenx_sites():

    api_url = "/v1/sites?excludeUnspecifiedSite=true"

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
        local_logger.error(f"Error getting bluecat addresses: {err}")
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

def get_clickhouse_sites():

  # Connect to ClickHouse
  livenx_ch_sites = []
  client = connect_with_tls(host=clickHouseHost, port=int(clickHouseApiPort), user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)

  # Define the query to retrieve all contents of the Network_Sites table
  query = "SELECT ID FROM Network_Sites"

  try:
      # Execute the query
      results = client.execute(query)

      # Process and display results
      for result in results:
          formatted_result = dict(zip(["id"], result))
          livenx_ch_sites.append(formatted_result)

  except Exception as e:
      local_logger.error(f"An error occurred while querying ClickHouse: {e}")
  finally:
      client.disconnect()
  return {"sites": livenx_ch_sites}

def diff_clickhouse_sites(livenx_sites_1, livenx_sites_2):
    livenx_sites_diff_list = []

    for livenx_site_1 in livenx_sites_1['sites']:
        livenx_site_found = False
        for livenx_site_2 in livenx_sites_2['sites']:
            if compare_livenx_site(livenx_site_1, livenx_site_2):
                livenx_site_found = True
                break
        if livenx_site_found == False:
            livenx_sites_diff_list.append(livenx_site_1)    
    return livenx_sites_diff_list

def add_to_clickhouse_sites(livenx_sites):

    # Connect to ClickHouse
    client = connect_with_tls(host=clickHouseHost, port=int(clickHouseApiPort), user=clickHouseUsername, password=clickHousePassword, database='inventory_db', ca_certs=clickhouseCACerts, certfile=clickhouseCertfile, keyfile=clickhouseKeyfile)
    
    for data in livenx_sites:

        # Check for valid uuid
        if is_valid_uuid(data.get('id')):
            ## Prepare columns for string values
            columns = [
                "ID", "Site_Name", "Site_Description", 
                "Type", "Is_Data_Center",
                "Is_Configured", "Contact_Name", "Phone_Number", 
                "Email"
                ]
            values = [
                data.get('id'),data.get("siteName",""), 
                data.get("siteDescription",""), data.get("type",""),
                data.get("isDataCenter",False),
                data.get("isConfigured",False), data.get('contactName',''),
                data.get('phoneNumber',''), data.get('email','')
            ]

            # check for site IP ids
            if data.get('siteIpRanges'):
                columns.append("Site_IP_Ranges")
                values.append(set(x for x in data.get("siteIpRanges",[])))
            if data.get('numberOfEmployees'):
                columns.append("Number_Of_Employees")
                values.append(data.get('numberOfEmployees'))
            # check for mailingAddress
            if data.get('mailingAddress'):
                address1 = data.get('mailingAddress',{}).get('address1')
                if address1:
                    columns.append("Mailing_Address.Address1")
                    values.append((address1,))
                address2 = data.get('mailingAddress',{}).get('address2')
                if address2:
                    columns.append("Mailing_Address.Address2")
                    values.append((address2,))
                city = data.get('mailingAddress',{}).get('city')
                if city:
                    columns.append("Mailing_Address.City")
                    values.append((city,))
                state = data.get('mailingAddress',{}).get('state')
                if state:
                    columns.append("Mailing_Address.State")
                    values.append((state,))
                zip = data.get('mailingAddress',{}).get('zip')
                if zip:
                    columns.append("Mailing_Address.ZIP")
                    values.append((zip,))
                country = data.get('mailingAddress',{}).get('country')
                if country:
                    columns.append("Mailing_Address.Country")
                    values.append((country,))
            # check for position
            if data.get('position'):
                latitude = data.get('position',{}).get('latitude')
                if latitude:
                    columns.append("Position.Latitude")
                    values.append((latitude,))
                longitude = data.get('position',{}).get('longitude')
                if longitude:
                    columns.append("Position.Longitude")
                    values.append((longitude,))
            # check for region
            if data.get('region'):
                id = data.get('region',{}).get('id')
                if id:
                    columns.append("Region.ID")
                    values.append((id,))
                longName = data.get('region',{}).get('longName')
                if longName:
                    columns.append("Region.Long_Name")
                    values.append((longName,))
                shortName = data.get('region',{}).get('shortName')
                if shortName:
                    columns.append("Region.Short_Name")
                    values.append((shortName,))
                type = data.get('region',{}).get('type')
                if type:
                    columns.append("Region.Type")
                    values.append((type,))
                parent = data.get('region',{}).get('parent')
                if parent:
                    columns.append("Region.Parent")
                    values.append((json.dumps(parent),))
            if data.get('tierCategoryId'):
                columns.append("Tier_Category_ID")
                values.append(data.get('tierCategoryId'))
            # check for devices
            if data.get('devices'):
                devices = data.get('devices',{}).get('devices',[])                
                columns.append("Devices.Device_Serial")
                columns.append("Devices.Device_Name")
                columns.append("Devices.Host_Name")
                columns.append("Devices.WAN")
                columns.append("Devices.Tagged_Omni")
                deviceSerial = []
                deviceName = []
                hostName = []
                wan = []
                taggedOmni = []
                for x in devices:
                    deviceSerial.append(x.get('deviceSerial',''))
                    deviceName.append(x.get('deviceName',''))
                    hostName.append(x.get('hostName',''))
                    wan.append(x.get('wan',False))
                    taggedOmni.append(x.get('taggedOmni',False))
                values.append(deviceSerial)
                values.append(deviceName)
                values.append(hostName)
                values.append(wan)
                values.append(taggedOmni)
            # check for businessHours
            if data.get('businessHours'):
                businessHours = data.get("businessHours",{})
                id = businessHours.get('id')
                if id:
                    columns.append("Business_Hours.ID")
                    values.append((id,))
                site = businessHours.get('site')
                if site:
                    columns.append("Business_Hours.Site")
                    values.append((site,))
                timeSettings = businessHours.get("timeSettings",{})
                if timeSettings:
                    columns.append("Business_Hours.Time_Settings")
                    days = timeSettings.get("days",[])
                    ch_days = [x for x in days]
                    ch_startTime = timeSettings.get("startTime")
                    ch_endTime = timeSettings.get("endTime")
                    ch_enableDst = timeSettings.get("enableDst")
                    timeZone = timeSettings.get("timeZone",{})
                    ch_timeZone = [(timeZone.get('displayValue'), timeZone.get('rawValue'))]
                    values.append([[(ch_days,ch_startTime,ch_endTime,ch_enableDst,ch_timeZone)]])
            # check for clientMessages
            if data.get('clientMessages'):
                columns.append("Client_Messages")
                values.append(set(x for x in data.get("clientMessages")))
            # check for tags
            if data.get('tags'):
                columns.append("Tags")
                values.append(set(x for x in data.get("tags")))
            #Prepare insert query
            insert_query = f"INSERT INTO Network_Sites ({','.join(columns)}) VALUES"
            try:
                # Execute the INSERT statement
                client.execute(insert_query, [tuple(values)])
                local_logger.info(f"Data inserted successfully for ID: {data.get('id')}")
            except Exception as e:
                local_logger.error(f"Error in ID: {data.get('id')} inserting data: {e}")
        else:
            local_logger.error(f"Error in invalid uid: {data.get('id')}")
  
