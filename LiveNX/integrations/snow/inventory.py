
#!/usr/bin/env python3

import os
import logging
import csv
from operator import getitem

local_logger = logging.getLogger(__name__)


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