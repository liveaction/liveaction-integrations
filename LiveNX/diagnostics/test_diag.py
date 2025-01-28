
import pytest
from .diag import version_ip, fetch_nodes, fetch_system_statistics, \
                    fetch_app_mailer_settings, fetch_syslog_config, \
                    fetch_snmp_trap_config, fetch_webhooks_config
import logging
local_logger = logging.getLogger(__name__)

@pytest.fixture(scope="session")
def session_data(request):
    # Access the custom command-line option using `request.config.getoption()`
    livenx_ip = request.config.getoption("--livenx_ip")
    livenx_port = request.config.getoption("--livenx_port")
    livenx_token = request.config.getoption("--livenx_token")
    
    # Return the parameter (or combine it with other values if necessary)
    return {"livenx_ip": livenx_ip, "livenx_port": livenx_port, "livenx_token": livenx_token}

def test_version_ip(session_data):
    '''
    Test to check the response for version ip
    '''
    rtnFlag = False
    livenx_ip=session_data.get('livenx_ip')
    livenx_port=session_data.get('livenx_port')
    livenx_token=session_data.get('livenx_token')
    with open("testcase_health_check.txt", 'a') as fw:
        rtnFlag = version_ip(livenx_ip,livenx_port,livenx_token, fw)

    assert True == rtnFlag

def test_fetch_nodes(session_data):
    '''
    Test to fetch nodes
    '''
    node_name_mapping = ""
    livenx_ip=session_data.get('livenx_ip')
    livenx_port=session_data.get('livenx_port')
    livenx_token=session_data.get('livenx_token')
    with open("testcase_health_check.txt", 'a') as fw:
        node_name_mapping = fetch_nodes(livenx_ip,livenx_port,livenx_token, fw)

    assert type(node_name_mapping) == dict

def test_fetch_system_statistics(session_data):
    '''
    Test to fetch system statistics
    '''
    rtnFlag = False
    livenx_ip=session_data.get('livenx_ip')
    livenx_port=session_data.get('livenx_port')
    livenx_token=session_data.get('livenx_token')
    with open("testcase_health_check.txt", 'a') as fw:
        rtnFlag = fetch_system_statistics(livenx_ip,livenx_port,livenx_token, fw)

    assert True == rtnFlag

def test_fetch_app_mailer_settings(session_data):
    '''
    Test to fetch app mailer settings
    '''
    rtnFlag = False
    livenx_ip=session_data.get('livenx_ip')
    livenx_port=session_data.get('livenx_port')
    livenx_token=session_data.get('livenx_token')
    with open("testcase_health_check.txt", 'a') as fw:
        rtnFlag = fetch_app_mailer_settings(livenx_ip,livenx_port,livenx_token, fw)

    assert True == rtnFlag

def test_fetch_syslog_config(session_data):
    '''
    Test to fetch app syslog config
    '''
    rtnFlag = False
    livenx_ip=session_data.get('livenx_ip')
    livenx_port=session_data.get('livenx_port')
    livenx_token=session_data.get('livenx_token')
    with open("testcase_health_check.txt", 'a') as fw:
        rtnFlag = fetch_syslog_config(livenx_ip,livenx_port,livenx_token, fw)

    assert True == rtnFlag
    
def test_fetch_snmp_trap_config(session_data):
    '''
    Test to fetch app snmp trap config
    '''
    rtnFlag = False
    livenx_ip=session_data.get('livenx_ip')
    livenx_port=session_data.get('livenx_port')
    livenx_token=session_data.get('livenx_token')
    with open("testcase_health_check.txt", 'a') as fw:
        rtnFlag = fetch_snmp_trap_config(livenx_ip,livenx_port,livenx_token, fw)

    assert True == rtnFlag

def test_fetch_webhooks_config(session_data):
    '''
    Test to fetch webhooks config
    '''
    rtnFlag = False
    livenx_ip=session_data.get('livenx_ip')
    livenx_port=session_data.get('livenx_port')
    livenx_token=session_data.get('livenx_token')
    with open("testcase_health_check.txt", 'a') as fw:
        rtnFlag = fetch_webhooks_config(livenx_ip,livenx_port,livenx_token, fw)

    assert True == rtnFlag
    