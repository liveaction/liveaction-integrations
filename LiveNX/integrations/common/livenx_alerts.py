import requests
import os
import logging
import ssl
import json
from datetime import datetime
import urllib.request, urllib.parse
from helper.clickhouse import connect_with_tls
from utils.custom_datetime import is_valid_iso_datetime

local_logger = logging.getLogger(__name__)

# Retrieve environment variables
liveNxHost = os.getenv("LIVENX_API_HOST","")
liveNxApiPort = os.getenv("LIVENX_API_PORT","")
liveNxToken = os.getenv("LIVENX_API_TOKEN","")

clickHouseHost = os.getenv("CLICKHOUSE_HOST","")
clickHouseUsername = os.getenv("CLICKHOUSE_USERNAME","")
clickHousePassword = os.getenv("CLICKHOUSE_PASSWORD","")
clickHouseApiPort = os.getenv("CLICKHOUSE_PORT","")

freshworkHost  = os.getenv("FRESHWORK_HOST","")
freshwork_username = os.getenv("FRESHWORK_USERNAME","")
freshwork_password = os.getenv("FRESHWORK_PASSWORD","")

def compare_livenx_alert(livenx_site_1, livenx_site_2):
    is_same = str(livenx_site_1.get('alertId')) == str(livenx_site_2.get('alertId'))
    return is_same

def create_request(url, data = None):
    if not liveNxHost or not liveNxApiPort or not liveNxToken:
        raise Exception("Missing LiveNx Env setup")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        'Authorization': f'Bearer {liveNxToken}',
    }
    api_url = "https://" + liveNxHost + ":" + liveNxApiPort + url

    request = urllib.request.Request(api_url, headers=headers, data = data)
    return request, ctx

# Function to get all alerts
def get_livenx_alerts(startTimeSecs, endTimeSecs):
    startTimeMillis = startTimeSecs * 1000
    endTimeMillis = endTimeSecs * 1000
    try:
        api_url = "/v1/alerting/alerts"

        request, ctx = create_request(api_url)
        request.add_header("Content-Type", "application/json")
        request.add_header("accept", "application/json")
        
        # Specify the request method as POST
        request.method = "GET"

        results = []
        with urllib.request.urlopen(request, context=ctx) as response:
            response_data = response.read().decode('utf-8')
            # Parse the JSON response
            json_data = json.loads(response_data)
            for alert in json_data:
                results.append(alert)

        return {"alerts": results}
        
    except requests.exceptions.HTTPError as errh:
        local_logger.info(f"Http Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        local_logger.info(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        local_logger.info(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        local_logger.info(f"An Error Occurred: {err}")

def push_livenx_alerts(alerts):
    pass ## needs to be implemented by LiveAction


def get_clickhouse_alerts():

  # Connect to ClickHouse
  livenx_ch_alerts = []
  client = connect_with_tls(host=clickHouseHost, port=int(clickHouseApiPort), user=clickHouseUsername, password=clickHousePassword, database='inventory_db')

  # Define the query to retrieve all contents of the Network_Sites table
  query = "SELECT Alert_Id FROM Alert_Inventory"

  try:
      # Execute the query
      results = client.execute(query)

      # Process and display results
      for result in results:
          formatted_result = dict(zip(["alertId"], result))
          livenx_ch_alerts.append(formatted_result)

  except Exception as e:
      local_logger.error(f"An error occurred while querying ClickHouse: {e}")
  finally:
      client.disconnect()
  return {"alerts": livenx_ch_alerts}

def diff_clickhouse_alerts(livenx_alerts_1, livenx_alerts_2):
    livenx_alerts_diff_list = []

    for livenx_site_1 in livenx_alerts_1['alerts']:
        livenx_site_found = False
        for livenx_site_2 in livenx_alerts_2['alerts']:
            if compare_livenx_alert(livenx_site_1, livenx_site_2):
                livenx_site_found = True
                break
        if livenx_site_found == False:
            livenx_alerts_diff_list.append(livenx_site_1)    
    return livenx_alerts_diff_list


def add_to_clickhouse_alerts(livenx_alerts):    
    # Connect to ClickHouse
    client = connect_with_tls(host=clickHouseHost, port=int(clickHouseApiPort), user=clickHouseUsername, password=clickHousePassword, database='inventory_db')

    for data in livenx_alerts:
        ## Prepare columns for string values
        columns = [
            "Version", "Alert_Id", "Type", 
            "Alert_Category", "Alert_Identifier_Id",
            "Duration_Since_Created_Minutes", 
            "Duration_Active_Minutes", "Severity", "User_Status", "Contributes_To_Status",
            "Alert_State"
            ]
        values = [
            data.get('version'),data.get("alertId",""), data.get("type",""), 
            data.get("alertCategory",""),data.get("alertIdentifierId",""),
            data.get('durationSinceCreatedMinutes',''),
            data.get('durationActiveMinutes',''),data.get('severity',''),data.get('userStatus',''),data.get('contributesToStatus',False),
            data.get('alertState','')
        ]
        dateCreated = data.get("dateCreated")
        if dateCreated and is_valid_iso_datetime(dateCreated):
            columns.append("Date_Created")
            values.append(datetime.strptime(dateCreated, "%Y-%m-%dT%H:%M:%S.%fZ"))
        dateClosed = data.get("dateClosed")
        if dateClosed and is_valid_iso_datetime(dateClosed):
            columns.append("Date_Closed")
            values.append(datetime.strptime(dateClosed, "%Y-%m-%dT%H:%M:%S.%fZ"))
        dateOfLastAlertStateChange = data.get("dateOfLastAlertStateChange")
        if dateOfLastAlertStateChange and is_valid_iso_datetime(dateOfLastAlertStateChange):
            columns.append("Date_Of_Last_Alert_State_Change")
            values.append(datetime.strptime(dateOfLastAlertStateChange, "%Y-%m-%dT%H:%M:%S.%fZ"))
        # check for description
        if data.get('description'):
            description = data.get('description',{})
            title = description.get('title',"")
            columns.append("Description_Title")
            values.append(title)

            summary = description.get('summary',"")
            columns.append("Description_Summary")
            values.append(summary)

            details = description.get('details',[])
            if len(details):
                columns.append("Description_Details")
                details_data = []
                for detail in details:
                    details_data.append((detail.get('label',''),detail.get('value',''),detail.get('notes','')))
                values.append(details_data)

            sourceInfos = description.get('sourceInfo',[])
            if len(sourceInfos):
                columns.append("Description_Source_Info")
                sourceInfo_data = []
                for sourceInfo in sourceInfos:
                    sourceInfo_data.append((sourceInfo.get('type',''),sourceInfo.get('label',''),sourceInfo.get('displayValue',''),json.dumps(sourceInfo.get('rawValue',{}))))
                values.append(sourceInfo_data)
            
            linkInfos = description.get('linkInfo',[])
            if len(linkInfos):
                columns.append("Description_Link_Info")
                linkInfo_data = []
                for linkInfo in linkInfos:
                    linkInfo_data.append((linkInfo.get('type',''),linkInfo.get('label',''),linkInfo.get('displayValue',''),json.dumps(linkInfo.get('rawValue',{}))))
                values.append(linkInfo_data)

            tableInfo = description.get('tableInfo')
            if tableInfo:
                label = tableInfo.get('label',"")
                columns.append("Description_Table_Info_Label")
                values.append(label)

                lx_columns = tableInfo.get('columns',[])
                if len(lx_columns):
                    columns.append("Description_Table_Info_Columns")
                    lx_column_data = []
                    for lx_column in lx_columns:
                        lx_column_data.append((lx_column.get('key',''),lx_column.get('label',''),lx_column.get('type','')))
                    values.append(lx_column_data)
                
                rows = tableInfo.get('rows',[])
                if len(rows):
                    columns.append("Description_Table_Info_Rows")
                    rows_data = []
                    for row in rows:
                        row_data = []
                        for k,y in row.items():
                            row_data.append((y.get('label',''),y.get('value',''),y.get('notes','')))
                        rows_data.append(row_data)                    
                    values.append(rows_data)
            
        if data.get('rootCauseAnalysis'):
            rootCauseAnalysis = data.get('rootCauseAnalysis',{})
            summary = rootCauseAnalysis.get('summary')
            if summary:
                columns.append("Root_Cause_Analysis_Summary")
                values.append(summary)
            chainId = rootCauseAnalysis.get('chainId')
            if chainId:
                columns.append("Root_Cause_Analysis_Chain_Id")
                values.append(chainId)
            issues = rootCauseAnalysis.get('issues',[])
            if len(issues):
                columns.append("Root_Cause_Analysis_Issues")
                issue_data = []
                for issue in issues:
                    issue_data.append((issue.get('issue',''),issue.get('recommendation','')))
                values.append(issue_data)
        alertIntegrations = data.get('alertIntegrations')
        if alertIntegrations:
            serviceNowAlertIntegration = alertIntegrations.get('serviceNowAlertIntegration',{})
            if serviceNowAlertIntegration:
                incidentNumber = serviceNowAlertIntegration.get('incidentNumber',"")
                columns.append("Alert_Integrations_ServiceNow_Alert_Integration_Incident_Number")
                values.append(incidentNumber)
                incidentUrl = serviceNowAlertIntegration.get('incidentUrl',"")
                columns.append("Alert_Integrations_ServiceNow_Alert_Integration_Incident_Url")
                values.append(incidentUrl)
        
        #Prepare insert query
        insert_query = f"INSERT INTO Alert_Inventory ({','.join(columns)}) VALUES"
        try:
            # Execute the INSERT statement
            client.execute(insert_query, [tuple(values)])
            local_logger.info(f"Data inserted successfully for Alert ID: {data.get('alertId')}")
        except Exception as e:
            local_logger.error(f"Error in Alert ID: {data.get('alertId')} inserting data: {e}")

def check_requester_freshwork():
    if not(freshworkHost and freshwork_username):
        raise Exception("Missing Freshwork Env setup") 
    api_url = "/api/v2/requesters?query=\"primary_email:'itsupport@livenx.com'\""

    requester_api_url = f"https://{freshworkHost}{api_url}"
    ## check if requester exist 
    res = requests.get(requester_api_url, 
                                auth=(freshwork_username, freshwork_password), 
                                verify=False, 
                                timeout=30)
    requester_id = None
    if res.status_code == 200:
        response = res.json()
        # response output
        # {'requesters': [
        #   {
        #       'active': True, 'address': None, 'background_information': None, 
        #       'can_see_all_changes_from_associated_departments': False, 
        #       'can_see_all_tickets_from_associated_departments': False, 
        #       'created_at': '2025-01-20T11:48:01Z', 'custom_fields': {}, 
        #       'department_ids': [56000231414], 'department_names': ['Development'], 
        #       'external_id': None, 'first_name': 'Pushpendra', 'has_logged_in': False, 
        #       'id': 56000339895, 'is_agent': False, 'job_title': None, 'language': 'en', 
        #       'last_name': 'Kushwaha', 'location_id': None, 'location_name': None,
        #       'mobile_phone_number': None, 
        #       'primary_email': 'pkkushwaha@liveaction.com', 'reporting_manager_id': None, 
        #       'secondary_emails': [], 'time_format': '12h', 'time_zone': 'Eastern Time (US & Canada)', 
        #       'updated_at': '2025-01-20T11:48:01Z', 'vip_user': False, 'work_phone_number': None
        # }]}
        requesters = response['requesters']
        if len(requesters) > 0:
            requester_id = requesters[0].get('id')
        else:
            api_url = "/api/v2/requesters"
            requester_api_url = f"https://{freshworkHost}{api_url}"
            # create payload
            # create_requester_data = {
            #     "first_name":"Ron","last_name":"Weasley","job_title":"Student",
            #     "primary_email":"ronald.weasley@hogwarts.edu",
            #     "secondary_emails":["ronald.weasley@freshservice.com", "ronald.weasley@freshworks.com"],
            #     "work_phone_number":"62443","mobile_phone_number":"77762443","department_ids":[554],
            #     "can_see_all_tickets_from_associated_departments":False,
            #     "reporting_manager_id":656,"address":"Gryffindor Tower",
            #     "time_zone":"Edinburgh","language":"en","location_id":23,
            #     "background_information":"","custom_fields":{
            #         "quidditch_role":None,
            #         "hogsmeade_permission":True
            #     }
            # }
            create_requester_data = {
                "first_name":"IT",
                "last_name":"Support",
                "primary_email":"itsupport@livenx.com"
            }
            res = requests.post(requester_api_url, 
                                    auth=(freshwork_username, freshwork_password), 
                                    verify=False, 
                                    timeout=30,
                                    json=create_requester_data)
            if res.status_code == 201:
                response = res.json()
                requester_id = response['requester'].get('id')
    return requester_id

def get_freshwork_alerts():
    if not(freshworkHost and freshwork_username):
        raise Exception("Missing Freshwork Env setup") 
    api_url = "/api/v2/tickets"
    api_url = f"https://{freshworkHost}{api_url}"
    ## check if requester exist 
    res = requests.get(api_url, 
                                auth=(freshwork_username, freshwork_password), 
                                verify=False)
    if res.status_code == 200:
        response = res.json()
        # response output
        # {'tickets': [{'subject': 'LiveNX Memory Utilization', 'group_id': None, 'department_id': None, 
        #               'category': 'SYSTEM', 'sub_category': None, 'item_category': None, 
        #               'requester_id': 56000433058, 'responder_id': None, 'due_by': '2025-01-29T16:46:07Z', 
        #               'fr_escalated': False, 'deleted': False, 'spam': False, 'email_config_id': None, 
        #               'fwd_emails': [], 'reply_cc_emails': [], 'cc_emails': [], 'is_escalated': False, 
        #               'fr_due_by': '2025-01-29T13:46:07Z', 'id': 90, 'priority': 4, 'status': 4, 'source': 2,
        #               'created_at': '2025-01-29T12:46:07Z', 'updated_at': '2025-01-29T12:46:07Z', 'workspace_id': 2,
        #               'requested_for_id': 56000433058, 'to_emails': None, 'type': 'Incident', 
        #               'description': '<div>Local/Server memory utilization returned below threshold</div>', 
        #               'description_text': 'Local/Server memory utilization returned below threshold', 
        #               'custom_fields': {
        #                   'major_incident_type': None, 'business_impact': None, 
        #                   'impacted_locations': None, 'no_of_customers_impacted': None, 
        #                   'custom_text': None}, 'tasks_dependency_type': 0}
        #             ]
        #     }
        return response
    return {}
def compare_freshwork_alert(livenx_alert_1, livenx_alert_2):    
    is_same = str(livenx_alert_1.get('alertId')) == str(livenx_alert_2.get('custom_fields').get('livenxalertid'))
    return is_same

def diff_freshwork_alerts(livenx_alerts_1, livenx_alerts_2):
    freshwork_alerts_alerts_diff_list = []

    for livenx_alert_1 in livenx_alerts_1['alerts']:
        freshwork_site_found = False
        for livenx_alert_2 in livenx_alerts_2['tickets']:
            if compare_freshwork_alert(livenx_alert_1, livenx_alert_2):
                freshwork_site_found = True
                break
        if freshwork_site_found == False:
            freshwork_alerts_alerts_diff_list.append(livenx_alert_1) 
    return freshwork_alerts_alerts_diff_list

def add_to_freshwork_alerts(livenx_alerts):    

    TICKET_SOURCE = {
        "email": 1,
        "portal":2,
        "phone": 3,
        "chat":	4,
        "feedback widget": 5,
        "yammer": 6,
        "aws cloudwatch": 7,
        "pagerduty": 8,
        "walkup": 9,
        "slack":10
    }

    TICKET_STATUS = {
        "open": 2,
        "pending": 3,
        "resolved": 4,
        "closed": 5
    }

    TICKET_PRIORITY={
        "low": 1,
        "medium": 2,
        "high": 3,
        "urgent": 4,
        "critical": 4
    }

    requester_id = check_requester_freshwork()

    if requester_id is None:
        raise Exception("requester Id is not setup")
    
    api_url = "/api/v2/tickets"
    api_url = f"https://{freshworkHost}{api_url}"
    for idx, data in enumerate(livenx_alerts):
        data = {
            "subject": data.get("description").get('title'),
            "description": data.get("description").get('summary'),
            "status": TICKET_STATUS.get(data.get("userStatus",'').lower()),
            "priority": TICKET_PRIORITY.get(data.get("severity",'').lower()),
            "category": data.get("alertCategory"),
            "urgency": 1,
            "impact": 1,
            "source": 2,
            "requester_id": requester_id,
            "custom_fields": {
                "livenxalertid": data.get("alertId")
            }
        }
        response = requests.post(api_url, 
                                auth=(freshwork_username, freshwork_password), 
                                verify=False, 
                                timeout=30,
                                json=data)
    return True