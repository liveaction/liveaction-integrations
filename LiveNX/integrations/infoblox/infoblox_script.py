import requests
import csv
import urllib3
import time
import json
import argparse
import logging
import sys

local_logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def pull_nat_data_from_LiveNX(livenx_host, livenx_token, start_time, end_time, report_id, device_serial):
    # Construct the LiveNX API URL
    livenx_nat_report_url = f'https://{livenx_host}:8093/v1/reports/flow/{report_id}/runAggregation.csv?startTime={start_time}&endTime={end_time}&deviceSerial={device_serial}'
    print(f"Constructed URL: {livenx_nat_report_url}")

    livenx_nat_data = []

    # Step 1: Pull NAT data from LiveNX as CSV
    headers = {'Accept': '*/*', 'Authorization': f'Bearer {livenx_token}'}
    try:
        print("Requesting NAT data from LiveNX...")
        livenx_response = requests.get(livenx_nat_report_url, headers=headers, verify=False, timeout=30)

        # Check the response status and print detailed logs
        print(f"LiveNX Response Status: {livenx_response.status_code}")
        if livenx_response.status_code == 200:
            print("LiveNX data fetched successfully.")
            print("LiveNX Response Content (First 500 chars):")
            print(livenx_response.text[:500])  # Print a portion to check content format

            # Check if the response contains data (empty CSV check)
            if not livenx_response.text.strip():
                print("LiveNX response contains no data.")
                livenx_nat_data = []
            else:
                # Split the response text into lines and check the length of the data
                livenx_nat_data = livenx_response.text.splitlines()
                print(f"Parsed LiveNX data into {len(livenx_nat_data)} lines.")
                if len(livenx_nat_data) < 2:  # There should be at least a header line and one data line
                    print("LiveNX CSV has no data rows.")
                    livenx_nat_data = []
        else:
            print(f"Error fetching LiveNX data: Status {livenx_response.status_code}, Content: {livenx_response.text}")
            livenx_nat_data = []
    except requests.exceptions.RequestException as e:
        print(f"Error pulling from LiveNX: {e}")
        livenx_nat_data = []

    return livenx_nat_data

# Step 2: Grab Infoblox DHCP leases
def get_infoblox(infoblox_host, infoblox_username, infoblox_password):

    # Infoblox API details
    wapi_version = '2.2'
    wapi_url = f'https://{infoblox_host}/wapi/v{wapi_version}'
    leases_url = f'{wapi_url}/lease?_return_fields=address,hardware&_max_results=1000'

    infoblox_leases = []
    try:
        print("Requesting DHCP lease data from Infoblox...")
        response = requests.get(leases_url, auth=(infoblox_username, infoblox_password), verify=False, timeout=30)

        # Check the response status and print detailed logs
        print(f"Infoblox Response Status: {response.status_code}")
        if response.status_code == 200:
            infoblox_leases = response.json()
            print(f"Infoblox returned {len(infoblox_leases)} leases.")
            print("Sample Infoblox Lease Data (First 3):")
            print(infoblox_leases[:3])  # Print first 3 leases for debugging
        else:
            print(f"Error fetching Infoblox data: Status {response.status_code}, Content: {response.text}")
            infoblox_leases = []
    except requests.exceptions.RequestException as e:
        print(f"Error pulling from Infoblox: {e}")
        infoblox_leases = []
    
    return infoblox_leases

def process_consolidation(livenx_nat_data, infoblox_leases):
    # Step 3: Match NAT IPs with DHCP leases and create a combined report
    consolidated_report = []
    print("Processing NAT and DHCP data for matching...")

    if livenx_nat_data:
        csv_reader = csv.DictReader(livenx_nat_data)
        for i, nat_entry in enumerate(csv_reader):
            src_ip = nat_entry.get('Src IP Addr')
            nat_ip = nat_entry.get('Mapped Src IP')
            dst_ip = nat_entry.get('Dst IP Addr')

            # Debug NAT entry content
            print(f"Entry {i}: Src IP - {src_ip}, Mapped Src IP - {nat_ip}, Dst IP - {dst_ip}")

            # Look for matching MAC address from DHCP leases
            mac_address = next((lease['hardware'] for lease in infoblox_leases if lease.get('address') == src_ip), None)

            # Debug MAC address match
            print(f"Matched MAC Address for Src IP {src_ip}: {mac_address}")

            # Pack everything into a report
            report_entry = {
                'SRC IP (private)': src_ip,
                'Mapped (NAT) IP': nat_ip,
                'DST IP (public)': dst_ip,
                'SRC MAC': mac_address
            }
            consolidated_report.append(report_entry)

    # Step 4: Check if any data was processed
    if not consolidated_report:
        print("No matching entries found between NAT and DHCP data.")
    else:
        print(f"Found {len(consolidated_report)} matching entries.")

    # Step 5: Save the report as a .json file
    output_file = 'consolidated_report.json'
    print(f"Saving report to {output_file}...")
    with open(output_file, 'w') as json_file:
        json.dump(consolidated_report, json_file, indent=4)

    print(f'Report saved as {output_file}')


def main(args):
    ## trace input arguments
    local_logger.info(args)

    # Assign variables from arguments
    livenx_host = args.livenx_host
    livenx_token = args.livenx_token
    device_serial = args.device_serial
    report_id = args.report_id
    infoblox_host = args.infoblox_host
    infoblox_username = args.infoblox_username
    infoblox_password = args.infoblox_password

    # Get the current time in milliseconds (Unix timestamp)
    end_time = int(time.time() * 1000)  # Current time in milliseconds
    start_time = end_time - (15 * 60 * 1000)  # Subtract 15 minutes

    livenx_nat_data = pull_nat_data_from_LiveNX(livenx_host, livenx_token, start_time, end_time, report_id, device_serial)
    infoblox_leases = get_infoblox(infoblox_host, infoblox_username, infoblox_password)
    process_consolidation(livenx_nat_data, infoblox_leases)
    



if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Script to fetch NAT data from LiveNX and DHCP leases from Infoblox, then consolidate into a report.")
    parser.add_argument("--livenx_host", required=True, help="LiveNX host IP address")
    parser.add_argument("--livenx_token", required=True, help="LiveNX API token")
    parser.add_argument("--report_id", required=True, help="Report Id for LiveNX")
    parser.add_argument("--device_serial", required=True, help="Device serial number for LiveNX")
    parser.add_argument("--infoblox_host", required=True, help="Infoblox host address")
    parser.add_argument("--infoblox_username", required=True, help="Infoblox username")
    parser.add_argument("--infoblox_password", required=True, help="Infoblox password")

    args = parser.parse_args()
    main(args)
