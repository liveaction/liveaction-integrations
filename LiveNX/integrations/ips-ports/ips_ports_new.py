#############################################################
############ Import the required modules/packages ###########
#############################################################
import json # For handling/parsing JSON data
import string
import time  # So we can set delays in retrieving report results while waiting for report to complete
import requests  # Facilitates HTTP/API Calls - This is the only one that I had to install (pip install requests)
import ipaddress  # Handles IP Address processing
from http.client import HTTPConnection  # Allows for more advanced HTTP debugging
import logging.handlers  # Used for SYSLOG AND SMTP Notifications
import logging  # Used for SYSLOG AND SMTP Notifications
import concurrent.futures    # Allows for multithreading
from os.path import join, dirname, abspath
import os

script_start = time.time()  # Used to track Total Script Run Time

#######################################################
############ Enable/Disable HTTP debugging ############
#######################################################
HTTPConnection.debuglevel = 0  # 0 = OFF, 1 = ON - HTTP debugging
requests.packages.urllib3.disable_warnings()  # Hides SSL Alerts/Errors. Comment out to see errors from Request module

#######################################
############ Set variables ############
#######################################
global Status
global Result
global url  # URL for API Call will be set/created below based on user input - DO NOT SET
global headers  # HEADER for API Call will be set/created below based on user input - DO NOT SET
global job
global B2B  # Variable for B2B List

Result = "" # Used later during the API Requests to LiveNX to store the "Resport Queing Details"
B2B = {}  # Used for B2B Mapping
B2B_IPs = {} # Used for IP Network mapping
flex_search = "flow.protocol!=ESP & flow.protocol!=UDP & tag=b2b & ( flow.dstIp=72.0.0.0/5 | flow.dstIp=192.0.0.0/5 | flow.dstIp=62.0.0.0/7 | flow.dstIp=64.0.0.0/7 ) "

B2B_NETWORK_FILE_PATH = os.getenv("B2B_NETWORK_FILE_PATH", "/opt/app/Files/B2B_Networks_l200.txt")
LOG_FILE_PATH = os.getenv('LOG_FILE_PATH','/opt/app/Files/LiveNX_B2Bl200.log')
OUTPUT_JSON_FILE = os.getenv('OUTPUT_JSON_FILE','/opt/app/Files/LiveNX_Results_l200.json')
FLEX_CRITERIA = os.getenv('FLEX_CRITERIA', flex_search)
REPORT_DATA_SOURCE = os.getenv('REPORT_DATA_SOURCE', 'flowstore')


syslog_server = os.getenv('SYSLOG_SERVER')  # SYSLOG/LOGGING # Remote Syslog Server
syslog_port = os.getenv('SYSLOG_PORT')  # SYSLOG/LOGGING # Remote Syslog Server

# Validate report data source
report_data_source = REPORT_DATA_SOURCE.strip().lower()
if report_data_source not in ("flowstore", "flowstore_v2"):
    raise ValueError("REPORT_DATA_SOURCE must be 'flowstore' or 'flowstore_v2'")

smtp_server = ""  # SMTP/LOGGING # SMTP Server
from_email = ""  # SMTP/LOGGING # SMTP source email address
to_email = ""  # SMTP/LOGGING # SMTP destination email address

################################################
############ LiveNX API Information ############
################################################
# User Configurable Settings: Will prompt if not set in code
nxserver = os.getenv('NX_SERVER')  # fqdn or IP of LiveNX Server - 192.168.1.10
apikey = os.getenv('API_KEY')  # API Key for your server - Example abcdefghiuL6pdDukxz2XEeijVqwRj11dg6dGIJvHqyoY=

# Get the env info if not set above:
if not nxserver:

    nxserver = input("Please enter FQDN or IP of your LiveNX Server: ")
    url = "https://{0}:8093/v1/reports/queue".format(nxserver)  # URL for API CALL

else:

    url = "https://{0}:8093/v1/reports/queue".format(nxserver)  # URL for API CALL

# Get the API KEY info and formatting
if not apikey:

    apikey = "Bearer {0}".format(input("Please enter your LiveNX API Key: "))

else:
    apikey = "Bearer {0}".format(apikey)


# Create Header
headers = {'accept': 'application/json', 'Accept-Encoding': 'gzip, deflate', 'Authorization': apikey,
           'Content-Type': 'application/json'}  # Header for API Request

#headers = {'accept': 'application/json', 'Authorization': apikey,
#           'Content-Type': 'application/json'}  # Header for API Request


def load_b2b_network_file():
    ########################################################
    ############ Open the B2B Source Data Files ############
    ########################################################
    with open(B2B_NETWORK_FILE_PATH) as file:
        # Iterate through the file grabbing the range and name (key and values) from each line and addthem to the dictionary
        for line in file:
            (range, name, threshold) = line.split()
            B2B[range] = name, threshold, ipaddress.IPv4Network(range)

    # Close the B2B source file
    file.close()

def setup_logger():
    ##################################################################################################
    ############  This section defines and configures the SYSLOG and SMTP Logging Options ############
    ##################################################################################################

    # Define logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Sets the logging level

    # Define the format/fields that will be sent in the message
    formatter = logging.Formatter('LiveNX_B2B: { "timestamp":"%(asctime)s",'
                                '"pathName":"%(pathname)s", "logRecordCreationTime":"%(created)f",'
                                '"functionName":"%(funcName)s", "levelNo":"%(levelno)s", "lineNo":"%(lineno)d",'
                                '"time":"%(msecs)d", "levelName":"%(levelname)s", "message":"%(message)s"}')

    # Define/Create a logging handler for a local log file
    file_handler = logging.FileHandler(LOG_FILE_PATH)  # Set log filename
    file_handler.setFormatter(formatter)  # Associate the format/fields with the filehandler

    if syslog_server and syslog_port:
        # Define/Create a logging handler for a remote syslog server
        remote_handler = logging.handlers.DatagramHandler(syslog_server, int(syslog_port))  # Set server name/address and port
        remote_handler.setFormatter(formatter)  # Associate the format/fields with the DatagramHandler

    # Define/Create a logging handler for sending email
    mail_handler = logging.handlers.SMTPHandler(mailhost=smtp_server,
                                                fromaddr=from_email,
                                                toaddrs=[to_email],
                                                subject='LiveNX_B2B Threshold Violation',
                                                # credentials=('user', 'pwd'),
                                                # secure=none
                                                )
    mail_handler.setFormatter(formatter)  # Associate the format/fields with the SMTPHandler

    # Associate the logging handlers with the logging process
    #logger.addHandler(remote_handler)  # Enables rsyslog
    logger.addHandler(file_handler)  # Enables local logging
    # logger.addHandler(mail_handler)     #Enables SMTP logging


def set_livenx_flow_limit():
    ##################################################################################################
    ############  This section handles submitting the API request to increase result size ############
    ##################################################################################################
    

    returnsize = "{ \"maxReturnSize\": 25000 }"  # Set's the JSON to bump results up to 10,000

    flowlimit = "https://{0}:8093/v1/reports/flow/limit".format(nxserver)  # URL for setting Flow Limit API CALL

    response = requests.put(url=flowlimit, headers=headers, verify=False, data=returnsize)  # Set the flow limit

def livenx_report_api_request():

    #############################################
    ############ Set the report JSON ############
    #############################################
    null = 'null'   # Allows null to equal "null" in the JSON below
    true = 'true'   # Allows true to equal "true" in the JSON below.  Note: "True" is reserved in Python
    false = 'false' # Allows false to equal "false" in the JSON below   Note: "False" is reserved in Python
    ReportJSON = [] # Set's Variable as a list
    flex = ""       # Set's the Variable flex to a string.
    # Read in the active IP address List as a "Flex Search" for inclusion in the JSON below:
    #for record in open('/opt/app/Files/B2B_Networks.txt').readlines(): flex += "flow.ip.dst={}".format(record.split()[0]) + " | "
    # for record in open('/opt/app/Files/B2B_Networks.txt').readlines(): flex += "flow.ip.dst={}".format(record.split()[0]) + " | "
    #
    # flex Network Coverage for l200 - 62.0.0.1 - 63.255.255.254, 64.0.0.1 - 65.255.255.254, 72.0.0.1 - 79.255.255.254, 192.0.0.1 - 199.255.255.254
    flex = flex.rstrip(' |')
    # flex = "flow.protocol!=ESP & flow.protocol!=UDP & tag=b2b & ( flow.dstIp=72.0.0.0/5 | flow.dstIp=192.0.0.0/5 | flow.dstIp=62.0.0.0/7 | flow.dstIp=64.0.0.0/7 ) "
    flex = FLEX_CRITERIA

    # Load the report configuration into a variable for later processing
    # Note: Original reports was ID:5, switching to ID:79 (IP AND PORTS)
    #            "startTime":1673504794000, to "endTime":1673504793700,
    #            id=5 if Top Conversations
    #            id=79 if Port
    #            direction can be outbound but using both to mine more data
    #
    ReportJson = {
    "name":"",
    "reports":[
        {
            "reportId":{
                "category":"flow",
                "id":"79"
            },
            "reportName":null,
            "reportDescription":null,
            "parameters":{
                "deviceSerial":"ALL_DEVICES_SERIAL",
                "direction":"outbound",
                "executionType":"timeseries",
                "startTime":null,
                "endTime":null,
                "flowType":"basic",
                "interface":"All Interfaces",
                "flexSearch":flex.rstrip(' |'),
                "reportDataSource":report_data_source,
                "sortBy":"BIT_RATE",
                "binDuration":"5min",
                "useFlowReportLimit":true
            }
        }
    ],  "priority":"P4",
    "classification":{
        "source":"OPERATIONS_DASHBOARD",
        "context":"REPORT"
    },
    "clientTimeParameters":{
        "relativeQueryTime":1200,
        "timeZone":{
            "id":"America/New_York",
            "enableDst":true
        },
        "customTime":false
    },
    "sharingConfig":[

    ],
    "timeZone":{
        "id":"America/New_York",
        "enableDst":true
    }
    }

    # Load report json into a variable for later use
    data = json.dumps(ReportJson)  # This is important. Don't remove!

    ##################################################################################################
    ############  This section handles submitting the API request to the LiveNX Server ############
    ##################################################################################################


    # Post the applications making sure to ignore the ssl certificates with verify=False
    response = requests.post(url=url, headers=headers, verify=False, data=data)

    # Retrieve the Report's Results URL from the Response
    # global Result
    Result = response.json()['jobInfo']['result']
    print(Result)



    ###################################################################################################
    ############ This section handles waiting for and retrieving the API/Report results ############
    ###################################################################################################

    # Check report completion status and loop until the report is ready
    complete = ""
    while not complete:
        try:
            # Result = "https://sedemo2.liveaction.com:8093/v1/reports/results/f314134e-3c85-4dc1-bb7a-1b70889cbbcf"

            # Submit API request to LiveNX to retrieve status and eventually completed report
            response = requests.get(url=Result, headers=headers, verify=False)
            if response.json()['userMessage']:
                print("Report's still processing...")
                time.sleep(1)
        except KeyError as error:  # Once the report is ready proceed
            complete = True
        except:
            print("Default Exception")
            pass

    return response


def save_api_response(response):
    ###########################################################
    ############ Stores data to file for debugging ############
    ############ KEEP COMMENTED OUT UNLESS DESIRED ############
    ###########################################################
    '''
    write_time = time.time()
    print('Writing API results to /opt/app/Files/LiveNX_Results.json')
    output_file = open('/opt/app/Files/LiveNX_Results_l200.json', 'w')
    json.dump(response.json(), output_file, indent=4)
    output_file.close()
    print(f'Data successfully written to file api.json.  Total "write" time took {round(time.time() - write_time, 2)}')
    '''
    #
    # New and Improved
    summarydata = response.json()['results'][0]['results'][0]['summary']['summaryData']  # Grab only the data we need
    enabled = True
    if enabled:
        write_time = time.time()
        print('Writing "Optimized" API results to Files/LiveNX_Results.json')
        output_file = open(OUTPUT_JSON_FILE, 'w')
        json.dump(summarydata, output_file, indent=4)
        output_file.close()
        print(f'Data successfully written to file api.json.  Total "write" time took {round(time.time() - write_time, 2)}')
    else:
        print("Writing JSON to disk is disabled")

def process_data(record):

    # Now that the report's JSON has been downloaded into the "response" varriable as a mix of JSON(dictionaries) and Lists
    # ...we need to find just the data we need.  In this case we're processing the summaryData.
    # ....Because there is a mix of dictionaries and lists, we're alternating between calling dictionary "key names" and numerical list ids.
    # ....Read this is "From the JSON loaded in the Response variable, grab the list associated with the "results" key...
    # .......Then from the selected list of dictionarys, retrieve the list stored is it's "result" key.  Then from the...
    # ........retrieved list of dictionarys, retrieve and iterate through the "summary" key and it's subkey "summaryData"

    # Set variables and process each record so that we can create/send logs when thresholds/matches are found

    #source_username = record['data'][0]['value']
    #destination_username = record['data'][1]['value']
    source_ip = record['data'][2]['value'].strip(
        string.ascii_letters + string.whitespace + string.punctuation)  # Makes sure that only digits are retrieved
    #source_site = record['data'][3]['value']
    source_port = record['data'][4]['value']
    destination_ip = record['data'][5]['value'].strip(
        string.ascii_letters + string.whitespace + string.punctuation)  # Makes sure that only digits are retrieved
    #destination_site = record['data'][6]['value']
    destination_port = record['data'][7]['value']
    #protocol = record['data'][8]['value']
    #dscp = record['data'][9]['value']
    #app_name = record['data'][10]['value']
    #total_flows = record['data'][11]['value']
    #total_bytes = record['data'][12]['value']
    #total_packets = record['data'][13]['value']
    bit_rate = round(record['data'][14]['value'], 3) # Round bitrate to two decimals
    #packet_rate = record['data'][15]['value']
    #peak_bit_rate = record['data'][16]['value']
    #peak_packet_rate = record['data'][17]['value']
    enabled = True
    if enabled:
        b2b_network = B2B_IPs.get(destination_ip)
        if b2b_network:

            if b2b_network == '-':  # IP is not available in the network list
                return

            [name, threshold, network] = B2B.get(b2b_network)

            # Log the results
            log_result(source_ip, source_port, destination_ip, destination_port, bit_rate, name, threshold)
        else:
            is_found = False
            for _, [name, threshold, network] in B2B.items():
                # if ipaddress.IPv4Address(destination_ip) in ipaddress.IPv4Network(network) and source_port not in [443,8443,1521,1433,1363,1364]:
                if ipaddress.IPv4Address(destination_ip) in network:
                    
                    # set IP network mapping
                    B2B_IPs[destination_ip] = str(network)

                    # Log the results
                    log_result(source_ip, source_port, destination_ip, destination_port, bit_rate, name, threshold)

                    is_found = True
                    break
            
            if not is_found:
                # No IP found in the network
                B2B_IPs[destination_ip] = '-'
    else:
        print("Logging is disabled")

def log_result(source_ip, source_port, destination_ip, destination_port, bit_rate, name, threshold):

    if "#N/A" in threshold: #Looks for thresholds that didn't match up during my excel/vlookup
        logging.info("The Destination IP address {} matches {} but the threshold is invalid".format(destination_ip, name))
    elif (bit_rate > float(threshold)): #Compares bit rate to the integer contained in threshold
        logging.info("Source IP {}, Source Port {}, Destination IP {}, Destination Port {}, Average Bit Rate {}, has exceeded the {} threshold of {}".format(source_ip, source_port, destination_ip, destination_port, bit_rate, name, threshold))
    else:
        logging.info("The IP address {} matches {} using ports {} to {} but the bitrate {} was not in violation of the threshold {}".format(destination_ip, name, source_port, destination_port, bit_rate, threshold))



def threading(records):
    for record in records:
        process_data(record) 


def main():

    load_b2b_network_file()  # Load network file
    setup_logger() # Setup logging

    report_start = time.time()
    set_livenx_flow_limit() # Set flow limit
    response = livenx_report_api_request() # Setup Report Queue and get data
    print(f'Total Reporting time: {round(time.time() - report_start, 2)} seconds')

    save_api_response(response) # Save LiveNX API results

    start_time = time.time()
    print(f"Starting to process {len(response.json()['results'][0]['results'][0]['summary']['summaryData']):,} records against {len(B2B):,} networks and thresholds for a total of {len(response.json()['results'][0]['results'][0]['summary']['summaryData']) * len(B2B):,} comparisons")
    threading(response.json()['results'][0]['results'][0]['summary']['summaryData'])
    print(f"Total processing time =  {round(time.time() - start_time, 2)} seconds")

    print(f'Total time for completion = {round(time.time() - script_start, 2)} seconds')


if __name__ == "__main__":
    main()