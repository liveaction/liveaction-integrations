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

LIVENX_JSON_DATA = None
LIVENX_CSV_DATA = None

with open(SCRIPT_DIR.joinpath("tests", "mock_LiveNX_data.json")) as config_file:
    LIVENX_JSON_DATA = json.load(config_file)

with open(SCRIPT_DIR.joinpath("tests", "mock_LiveNX_data.csv")) as csv_file:
    LIVENX_CSV_DATA = csv_file.readlines()

def test_old_script():
    '''To test old script file'''
    LOG_FILE_PATH = os.getenv('LOG_FILE_PATH')
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)   

    ip_ports = importlib.import_module("ips-ports") 

    start_time = time.time()
    ip_ports.threading(LIVENX_JSON_DATA)
    print(f"**** OLD processing time =  {round(time.time() - start_time, 2)} seconds")


def test_new_script():
    '''To test new script for optimization'''
    ips_ports_new.load_b2b_network_file()
    
    ips_ports_new.LOG_FILE_PATH = ips_ports_new.LOG_FILE_PATH.replace('LiveNX_B2Bl200', 'LiveNX_B2Bl200_new')
    if os.path.exists(ips_ports_new.LOG_FILE_PATH):
        os.remove(ips_ports_new.LOG_FILE_PATH) 
    
    ips_ports_new.setup_logger()
    
    start_time = time.time()
    ips_ports_new.processing(LIVENX_CSV_DATA)
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
    ips_ports_new.LOG_FILE_PATH = ips_ports_new.LOG_FILE_PATH.replace('LiveNX_B2Bl200', 'tests/test')
    if os.path.exists(ips_ports_new.LOG_FILE_PATH):
        os.remove(ips_ports_new.LOG_FILE_PATH) 

    ips_ports_new.setup_logger()
    
    #------------------------
    # Setup LiveNX data
    #------------------------
    def generate_livenx_csv_records(data):

        rows = ['Src IP Addr,Src Site,Src Port,Dst IP Addr,Dst Site,Dst Port,Protocol,DSCP,Application,Total Flows (flows),Total Bytes (bytes),Total Packets (packets),Average Bit Rate (Kbps),Average Packet Rate (pps),Peak Bit Rate (bps),Peak Packet Rate (pps)']
        for (src_ip, dst_ip, bit_rate) in data:
             rows.append(f'{src_ip},Internet,443,{dst_ip},Unknown,"57,840",TCP,0 (BE),https,37,"8,974,646","13,912",{bit_rate},3.86,"25,872.85",5.01')
        return rows

    TEST_LIVENX_DATA = generate_livenx_csv_records([
        ('56.207.109.25', '10.164.0.101', 101),
        ('56.207.109.25', '10.164.0.24', 50),
        ('56.207.109.25', '56.207.109.91', 21),
        ('56.207.109.91', '10.164.0.101', 31),
        ('56.207.109.25', '56.207.109.91', 25)
    ])
    
    #------------------------
    # Process data
    #------------------------
    ips_ports_new.processing(TEST_LIVENX_DATA)


    #------------------------
    # Check Logs
    #------------------------
    with open(ips_ports_new.LOG_FILE_PATH) as logs:
        lines = logs.readlines()
        assert len(lines) == 3
        assert " has exceeded the thirdHost threshold " in lines[0]
        assert "was not in violation of the threshold" in lines[1]

        





