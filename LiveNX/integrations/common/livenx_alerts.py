import requests
import os
import logging
# from dotenv import load_dotenv
# load_dotenv()

logger = logging.getLogger(__name__)

# Retrieve environment variables
liveNxHost = os.getenv("LIVENX_API_HOST")
liveNxApiPort = os.getenv("LIVENX_API_PORT")
liveNxToken = os.getenv("LIVENX_API_TOKEN")

headers = {
    'Authorization': f'Bearer {liveNxToken}',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

# Function to get all alerts
def get_livenx_alerts(startTimeSecs, endTimeSecs):
    startTimeMillis = startTimeSecs * 1000
    endTimeMillis = endTimeSecs * 1000
    try:
        results = []
        api_url = f"https://{liveNxHost}:{liveNxApiPort}/v1/alerting/alerts"
        # if startTimeMillis != 0:
        #     api_url += "?startTime=" + str(startTimeMillis)
        #     if endTimeMillis != 0:
        #         api_url += "&endTime=" + str(endTimeMillis)
        logger.info(api_url)
        response = requests.get(api_url, headers=headers, verify=False)
        response.raise_for_status()  # Check for HTTP errors

        # Process the JSON response
        alerts = response.json()
        for alert in alerts:
            results.append({
                'alertId': alert.get('alertId'),
                'title':alert.get('description').get('title'),
                'description':alert.get('description').get('summary'),
                'category': alert.get('alertCategory'),
                'subcategory': alert.get('alertCategory'),
                'type': alert.get('type'),
                'severity': alert.get('severity'),
                'userStatus': alert.get('userStatus'),
                'serviceNowAlertIntegration': alert.get('alertIntegrations').get('serviceNowAlertIntegration'),
            })
        return results
    except requests.exceptions.HTTPError as errh:
        logger.info(f"Http Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        logger.info(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        logger.info(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        logger.info(f"An Error Occurred: {err}")

def push_livenx_alerts(alerts):
    pass ## needs to be implemented by LiveAction


