
#!/usr/bin/env python3

import os, json
import requests
import logging
import csv
from operator import getitem

local_logger = logging.getLogger(__name__)

servicenowHost = os.getenv("SERVICENOW_API_HOST")
servicenowUser = os.getenv("SERVICENOW_API_USER")
servicenowPass = os.getenv("SERVICENOW_API_PASSWORD")

def create_incident(data):
    """
        Method to create incident alert with below Payload
        {
            'number': incident.get('alertId'),
            'short_description':incident.get('description'),
            'description':incident.get('description'),
            'category': incident.get('category'),
            'subcategory': incident.get('category'),
            "urgency": urgency,
            "impact": impact,
            "contact_type": "self-service",
            "incident_state": "1",
        }
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    api_url = "/api/now/table/incident"
    url = f"https://{servicenowHost}{api_url}"
    
    auth = (servicenowUser, servicenowPass)

    response = requests.post(url, auth=auth, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        print(f"Incident created successfully--{response.content}")
        # return json.loads(response.content)
    else:
        print(f"Error creating incident: {response.status_code} - {response.content}")
        # return None

def get_priority_based_urgency_impact(severity):
    """
        Method to get urgency and impct based on severity value
        Required for Service Now
    """
    local_logger.info(f"Severity: {severity}")
    if severity == 'Critical':
        return 1,1
    elif severity == 'High':
        return 1,2
    elif severity == 'Moderate':
        return 1,3
    else:
        return 3,3
        

def push_servicenow_incidents(incidents):
    """
        Method to push all incident alert to Service Now
    """

    for incident in incidents:
        local_logger.info(f"alertId: {incident.get('alertId')}")
        urgency,impact = get_priority_based_urgency_impact(incident.get('severity'))
        data = {
            'number': incident.get('alertId'),
            'short_description':incident.get('description'),
            'description':incident.get('description'),
            'category': incident.get('category'),
            'subcategory': incident.get('category'),
            "urgency": urgency,
            "impact": impact,
            "contact_type": "self-service",
            "incident_state": "1",
        }
        create_incident(data)

def get_servicenow_incidents():
    """
        Method to get all incident alert from Service Now
    """

    results = []

    # page data object for iterating servicenow search results
    # pageData = {'sysparm_offset': 0, 'pageSize': 1000, 'sysparm_limit': 1000}
    # queries = {'queries' : ["severity=CRITICAL", "hostname=web"]}
    # sortColumn = {'sortColumn': 'modified'}
    # descending =  {'descending': True}

    api_url = "/api/now/table/incident"
    auth = (servicenowUser, servicenowPass)
    try:
        api_url = f"https://{servicenowHost}{api_url}?sysparm_limit=2"
        # if startTimeMillis != 0:
        #     api_url += "?startTime=" + str(startTimeMillis)
        #     if endTimeMillis != 0:
        #         api_url += "&endTime=" + str(endTimeMillis)
        local_logger.info(api_url)
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        response = requests.get(api_url, auth=auth, headers=headers, verify=False)
        response.raise_for_status()  # Check for HTTP errors

        # Process the JSON response
        alerts = response.json()
        for alert in alerts.get('result',[]):
            results.append({
                'number': alert.get('number'),
                'short_description':alert.get('short_description'),
                'description':alert.get('description'),
                'category': alert.get('category'),
                'subcategory': alert.get('subcategory'),
                "urgency": alert.get('urgency'),
                "impact": alert.get('impact'),
                "contact_type": alert.get('contact_type'),
                "incident_state": alert.get('incident_state'),
                "alertIntegrations": alert.get('opened_by').get('link'),
            })
        return results
    except requests.exceptions.HTTPError as errh:
        local_logger.info(f"Http Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        local_logger.info(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        local_logger.info(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        local_logger.info(f"An Error Occurred: {err}")

def getCsvDictData(file_path):
    #Open the CSV File
    if not file_path:
        raise Exception("Missing CSV file path") 
    
    devices = {}
    with open(file_path) as source_file:
        #Read the file into a dictionary
        reader = csv.DictReader(source_file)
        rownum = 0
        for snow_inventroy in reader:
            if snow_inventroy['u_associated_mnemonic'] and snow_inventroy['ip_address']:
                devices[rownum] = snow_inventroy
                rownum += 1
    return devices

def get_snow_inventory(file_path):
    
    snow_devices = getCsvDictData(file_path)

    #Sort records based on mnemonic
    alphamnemonic = iter((sorted(snow_devices.items(), key=lambda x: getitem(x[1], 'u_associated_mnemonic'))))
    ip_address = ""
    #Build API Command that adds all of the IP addresses from records with the same mnemonic
    associated_mnemonic = {}
    for row in alphamnemonic:
        #Store current Dictionary from Current Row & current mnenomic NAME from Current Dictionary
        currentrecord = row[1]
        currentname = currentrecord['u_associated_mnemonic']
        ip_address = currentrecord['ip_address']
        #Check to see if this if the first run, if previousname is empty, set previousname to current name
        if not associated_mnemonic.get(currentname):
            associated_mnemonic[currentname] = {
               "name":currentname,
               "ipRanges":[ip_address],
               "portMap":{
                       "protocols":[],
                       "portRanges":[]
                      },
                "nbarIds":[],
                "dscpTypes":[]
              }
        else:
            associated_mnemonic[currentname]['ipRanges'].append(ip_address)
    return associated_mnemonic.values()



def get_diff_snow_inventory(snow_inventories, livenx_custom_inventories):
    diff_snow_devices = []

    for device_1 in snow_inventories:
        livenx_device_found = False
        for device_2 in livenx_custom_inventories:
            if device_1.get('name') == device_2.get('name'):
                livenx_device_found = True
                break
        if livenx_device_found == False:
            diff_snow_devices.append(device_1)   
    return diff_snow_devices