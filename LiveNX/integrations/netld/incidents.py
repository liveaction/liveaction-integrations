
#!/usr/bin/env python3

import os
from jsonrpc import JsonRpcProxy
import logging
local_logger = logging.getLogger(__name__)

thirdeyeHost = os.getenv("THIRDEYE_API_HOST")
thirdeyeUser = os.getenv("THIRDEYE_API_USER")
thirdeyePass = os.getenv("THIRDEYE_API_PASSWORD")
thirdeyeNetwork = os.getenv("THIRDEYE_NETWORK")

def push_netld_incidents(incidents):
    ### Create a JSON-RPC proxy for the incidents service
    ###
    _netld_svc = JsonRpcProxy.fromHost(thirdeyeHost, thirdeyeUser, thirdeyePass)

    # page data object for iterating ThirdEye inventory search results
    pageData = {'offset': 0, 'pageSize': 500}
    incidents = {}

    while True:
        pageData = _netld_svc.call('Incident.create') ## needs to be implemented 

        if pageData['total'] == 0:
            break

        # remove IPs from 'addresses' that already exist in ThirdEye
        for device in pageData['devices']:
            incidents.pop(device['ipAddress'], None)

        # break if we've reached the end
        if pageData['offset'] + pageData['pageSize'] >= pageData['total']:
            break

        # next page
        pageData['offset'] += pageData['pageSize']

    for addr in incidents.keys():
        error = _netld_svc.call('Inventory.createDevice', 'Default', addr)

        if error != None:
             local_logger.info('Inventory.createDevicer: ' + str(error))

        local_logger.info(addr)


    ### Logout using the security service to be nice to the server
    ###
    _netld_svc.call('Security.logoutCurrentUser')

def get_netld_incidents():
    ### Create a JSON-RPC proxy for the inventory service
    ###
    devices = []
    _netld_svc = JsonRpcProxy.fromHost(thirdeyeHost, thirdeyeUser, thirdeyePass)

    # page data object for iterating ThirdEye inventory search results
    pageData = {'offset': 0, 'pageSize': 500}
    queries = {'queries' : ["severity=CRITICAL", "hostname=web"]}
    sortColumn = {'sortColumn': 'modified'}
    descending =  {'descending': True}
    while True:

        pageData = _netld_svc.call('Incident.search', pageData)

        if pageData['total'] == 0:
            break

        for device in pageData['devices']:
            devices.append(device)

        # break if we've reached the end
        if pageData['offset'] + pageData['pageSize'] >= pageData['total']:
            break

        # next page
        pageData['offset'] += pageData['pageSize']


    ### Logout using the security service to be nice to the server
    ###
    _netld_svc.call('Security.logoutCurrentUser')
    return devices