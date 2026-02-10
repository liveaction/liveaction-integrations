import ipaddress
import json
import sys
from pathlib import Path

import pytest
import runpy
import random
import requests
import time

import importlib  


import os

SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))


def load_env_file(dotenv_path, override=False):
    with open(dotenv_path) as file_obj:
        lines = file_obj.read().splitlines()  # Removes \n from lines

    dotenv_vars = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", maxsplit=1)
        dotenv_vars.setdefault(key, value)

    if override:
        os.environ.update(dotenv_vars)
    else:
        for key, value in dotenv_vars.items():
            os.environ.setdefault(key, value)

load_env_file(SCRIPT_DIR.joinpath('.env'), True)
import ips_ports_new

LIVENX_DATA = None

with open(SCRIPT_DIR.joinpath("mock_LiveNX_data.json")) as config_file:
    LIVENX_DATA = json.load(config_file)

def test_old_script():
    '''To test old script file'''
    LOG_FILE_PATH = os.getenv('LOG_FILE_PATH')
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)   

    ip_ports = importlib.import_module("ips-ports") 

    start_time = time.time()
    ip_ports.threading(LIVENX_DATA)
    print(f"**** OLD processing time =  {round(time.time() - start_time, 2)} seconds")


def test_new_script():
    '''To test new script for optimization'''
    ips_ports_new.load_b2b_network_file()
    
    ips_ports_new.LOG_FILE_PATH = ips_ports_new.LOG_FILE_PATH.replace('LiveNX_B2Bl200', 'LiveNX_B2Bl200_new')
    if os.path.exists(ips_ports_new.LOG_FILE_PATH):
        os.remove(ips_ports_new.LOG_FILE_PATH) 
    
    ips_ports_new.setup_logger()
    
    start_time = time.time()
    ips_ports_new.threading(LIVENX_DATA)
    print(f"**** NEW processing time =  {round(time.time() - start_time, 2)} seconds")


def test_new_process():
    #------------------------
    # Setup B2B data
    #------------------------
    B2B_threshold_data = """192.0.0.0/5 firstHost 10.5
    62.0.0.0/7 secondHost 5.0
    10.0.0.0/8 thirdHost 51.0
    """

    ips_ports_new.B2B = {}
    ips_ports_new.B2B_IPs = {}
    
    for line in B2B_threshold_data.split('\n'):
        line = line.strip()
        if line:
            (range, name, threshold) = line.strip().split()
            ips_ports_new.B2B[range] = name, threshold, ipaddress.IPv4Network(range)


    #------------------------
    # Setup logger
    #------------------------
    ips_ports_new.LOG_FILE_PATH = ips_ports_new.LOG_FILE_PATH.replace('LiveNX_B2Bl200', 'test')
    if os.path.exists(ips_ports_new.LOG_FILE_PATH):
        os.remove(ips_ports_new.LOG_FILE_PATH) 

    ips_ports_new.setup_logger()
    
    #------------------------
    # Setup LiveNX data
    #------------------------
    def generate_livenx_record(src_ip, dst_ip, bit_rate):
        record = {
        "key": [
            {
                "infoElementId": "100000008c229fa4",
                "value": src_ip
            },
            {
                "infoElementId": "100000008c229fa5",
                "value": dst_ip
            },
            {
                "infoElementId": "1000000000000004",
                "value": "TCP"
            },
            {
                "infoElementId": "1000000000000007",
                "value": 443
            },
            {
                "infoElementId": "100000000000000b",
                "value": 58203
            },
            {
                "infoElementId": "10000000000000c3",
                "value": "0 (BE)"
            },
            {
                "infoElementId": "1000000000000060",
                "value": "https"
            },
            {
                "infoElementId": "100000008c2297d0",
                "value": "Unknown"
            }
        ],
        "data": [
            {
                "infoElementId": "100000008c2298a4",
                "value": "null"
            },
            {
                "infoElementId": "100000008c2298a5",
                "value": "null"
            },
            {
                "infoElementId": "100000008c229fa4",
                "value": src_ip
            },
            {
                "infoElementId": "100000008c2297cf",
                "value": "Internet"
            },
            {
                "infoElementId": "1000000000000007",
                "value": 443
            },
            {
                "infoElementId": "100000008c229fa5",
                "value": dst_ip
            },
            {
                "infoElementId": "100000008c2297d0",
                "value": "Unknown"
            },
            {
                "infoElementId": "100000000000000b",
                "value": 58203
            },
            {
                "infoElementId": "1000000000000004",
                "value": "TCP"
            },
            {
                "infoElementId": "10000000000000c3",
                "value": "0 (BE)"
            },
            {
                "infoElementId": "1000000000000060",
                "value": "https"
            },
            {
                "infoElementId": "100000000000002a",
                "value": 40
            },
            {
                "infoElementId": "1000000000000017",
                "value": 96534560
            },
            {
                "infoElementId": "1000000000000018",
                "value": 77960
            },
            {
                "infoElementId": "100000008c22977d",
                "value": bit_rate
            },
            {
                "infoElementId": "100000008c22977e",
                "value": 21.655555555555555
            },
            {
                "infoElementId": "100000008c229846",
                "value": 257424.0
            },
            {
                "infoElementId": "100000008c229847",
                "value": 25.0
            }
            ]
        } 
        return record

    TEST_LIVENX_DATA = [
        generate_livenx_record('56.207.109.25', '10.164.0.101', 101),
        generate_livenx_record('56.207.109.25', '10.164.0.24', 50),
        generate_livenx_record('56.207.109.25', '56.207.109.91', 21),
        generate_livenx_record('56.207.109.91', '10.164.0.101', 31),
        generate_livenx_record('56.207.109.25', '56.207.109.91', 25)
    ]
    
    #------------------------
    # Process data
    #------------------------
    ips_ports_new.threading(TEST_LIVENX_DATA)


    #------------------------
    # Check Logs
    #------------------------
    with open(ips_ports_new.LOG_FILE_PATH) as logs:
        for log in logs:
            print(log)

        





