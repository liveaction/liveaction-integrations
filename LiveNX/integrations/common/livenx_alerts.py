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
