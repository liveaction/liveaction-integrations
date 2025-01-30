from common.livenx_alerts import check_requester_freshwork, add_to_freshwork_alerts
import logging
local_logger = logging.getLogger(__name__)

def test_check_requester_freshwork():
    '''
    test include to check the response for requester_id api call
    '''
    requester_id = check_requester_freshwork()
    assert type(requester_id) == int

def test_add_to_freshwork_alerts():
    data = {
        "alerts":[
            {
                "version": "1",
                "alertId": "07872244-c185-45ae-a68e-5620c47be504",
                "type": "DEVICE_CPU",
                "alertCategory": "SYSTEM",
                "alertIdentifierId": "276c4af4-1155-4ea0-b744-281eb20c6c0e",
                "dateCreated": "2025-01-29T08:13:41.361Z",
                "dateClosed": "2025-01-29T08:25:01.258Z",
                "durationSinceCreatedMinutes": 16,
                "durationActiveMinutes": 11,
                "severity": "Critical",
                "userStatus": "RESOLVED",
                "contributesToStatus": False,
                "alertState": "INACTIVE_CLEARED",
                "dateOfLastAlertStateChange": "2025-01-29T08:25:01.258Z",
                "description": {
                    "title": "Device CPU Utilization",
                    "summary": "livewire-greenville CPU utilization returned below threshold",
                    "details": [
                        {
                            "label": "Configured Threshold",
                            "value": "40 %"
                        },
                        {
                            "label": "Initial CPU Percentage",
                            "value": "56 %"
                        },
                        {
                            "label": "Latest CPU Percentage",
                            "value": "18 %"
                        },
                        {
                            "label": "AI Analysis Levels",
                            "value": "Basic Analysis"
                        }
                    ],
                    "sourceInfo": [
                        {
                            "type": "TEXT",
                            "label": "Region",
                            "displayValue": "Greenville, South Carolina, United States, North America",
                            "rawValue": "Greenville, South Carolina, United States, North America"
                        },
                        {
                            "type": "SITE",
                            "label": "Site",
                            "displayValue": "GreenvilleEdge",
                            "rawValue": {
                                "siteName": "GreenvilleEdge"
                            }
                        },
                        {
                            "type": "DEVICE",
                            "label": "Device",
                            "displayValue": "livewire-greenville",
                            "rawValue": {
                                "deviceSerial": "10.4.205.61:1731526492007",
                                "deviceName": "livewire-greenville"
                            }
                        }
                    ]
                },
                "alertIntegrations": {
                    "serviceNowAlertIntegration": None
                }
            }
        ]
    }
    ticket = add_to_freshwork_alerts(data)
    assert type(ticket) == bool
    