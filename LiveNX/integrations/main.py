#!/usr/bin/env python3

import sys
import os
import argparse
import logging

# Add the directory containing common.py to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, 'common'))
sys.path.insert(0, os.path.join(script_dir, 'netld'))

from common.livenx_inventory import get_livenx_inventory, add_to_livenx_inventory, \
    remove_from_livenx_inventory, diff_livenx_inventory, \
    get_livenx_ch_inventory, map_livenx_inventory_to_livenx_ch_inventory, diff_livenx_ch_inventory, \
    add_to_livenx_ch_inventory, remove_from_livenx_ch_inventory,  get_bluecat_addresses, \
    diff_bluecat_addresses
from netld.incidents import push_netld_incidents, get_netld_incidents
from common.livenx_alerts import push_livenx_alerts, get_livenx_alerts, get_clickhouse_alerts, add_to_clickhouse_alerts, diff_clickhouse_alerts
from netld.inventory import add_to_netld_inventory, remove_from_netld_inventory, get_netld_inventory, map_livenx_inventory_to_netld_inventory, map_netld_inventory_to_livenx_inventory
from helper.timer import get_top_of_current_minute_epoch
from helper.prompt import query_yes_no
from servicenow.incidents import get_servicenow_incidents, push_servicenow_incidents
from common.livenx_sites import get_bluecat_blocks, get_livenx_sites, map_bluecat_blocks_to_livenx_sites, diff_bluecat_sites, add_to_livenx_sites, get_clickhouse_sites, diff_clickhouse_sites, add_to_clickhouse_sites

from config.logger import setup_logger
local_logger = None

import time

def main(args):
    global local_logger
    local_logger = setup_logger(__name__, args.logstdout, logging.DEBUG)
    ## trace input arguments
    local_logger.info(args)
    # logging.basicConfig(filename='livenx-integrations.log', level=logging.INFO)
    starttimesecs = args.starttimesecs
    endtimesecs = args.endtimesecs

    if args.continuous and starttimesecs == 0 and endtimesecs == 0:
        num_minutes_behind = args.num_minutes_behind
        starttimesecs = get_top_of_current_minute_epoch() - (60 * (num_minutes_behind + 1))
        endtimesecs = get_top_of_current_minute_epoch() - (60 * num_minutes_behind)

    while True:
        if args.inventory:
            if args.fromproduct == "livenx" and args.toproduct == "netld":
                ## figure out which devices to add
                orig_livenx_inventory = get_livenx_inventory()
                orig_netld_inventory = get_netld_inventory()
                new_livenx_inventory = map_netld_inventory_to_livenx_inventory(orig_netld_inventory)
                livenx_inventory_diff_to_add = diff_livenx_inventory(orig_livenx_inventory, new_livenx_inventory)
                netld_inventory_diff_to_add = map_livenx_inventory_to_netld_inventory(livenx_inventory_diff_to_add)

                ## Prompt only Hostname instead of full inventory
                if len(netld_inventory_diff_to_add) > 0:
                    add_livenx_inventory_prompt = [ {
                        'hostname': invetory_diff.get('hostname')
                    } for invetory_diff in netld_inventory_diff_to_add]
                    if args.noprompt == True or query_yes_no("This inventory will be added: " + str(add_livenx_inventory_prompt)):
                        add_to_netld_inventory(netld_inventory_diff_to_add)

                # ## figure out which devices to remove
                livenx_inventory_diff_to_remove = diff_livenx_inventory(new_livenx_inventory, orig_livenx_inventory)
                netld_inventory_diff_to_remove = map_livenx_inventory_to_netld_inventory(livenx_inventory_diff_to_remove)
                ## Prompt only Hostname instead of full inventory
                
                if len(netld_inventory_diff_to_remove) > 0:
                    remove_livenx_inventory_prompt = [ {
                        'hostname': invetory_diff.get('hostname')
                    } for invetory_diff in livenx_inventory_diff_to_remove]
                    if args.noprompt == True or query_yes_no("This inventory will be removed: " + str(remove_livenx_inventory_prompt)):
                        remove_from_netld_inventory(netld_inventory_diff_to_remove)
            elif args.fromproduct == "netld" and args.toproduct == "livenx":
                ## figure out which devices to add
                orig_livenx_inventory = get_livenx_inventory()
                orig_netld_inventory = get_netld_inventory()
                new_livenx_inventory = map_netld_inventory_to_livenx_inventory(orig_netld_inventory)
                livenx_inventory_diff_to_add = diff_livenx_inventory(new_livenx_inventory, orig_livenx_inventory)

                if len(livenx_inventory_diff_to_add) > 0:
                    if args.noprompt == True or query_yes_no("This inventory will be added: " + str(livenx_inventory_diff_to_add)):
                        add_to_livenx_inventory(livenx_inventory_diff_to_add)

                ## figure out which devices to remove
                livenx_inventory_diff_to_remove = diff_livenx_inventory(orig_livenx_inventory, new_livenx_inventory)

                if len(livenx_inventory_diff_to_remove) > 0:
                    if args.noprompt == True or query_yes_no("This inventory will be removed: " + str(livenx_inventory_diff_to_remove)):
                        remove_from_livenx_inventory(livenx_inventory_diff_to_remove)
            elif args.fromproduct == "livenx" and args.toproduct == "livenxch":
                ## sync the LiveNX inventory to the Clickhouse inventory
                ## figure out which devices to add
                orig_livenx_inventory = get_livenx_inventory()
                orig_livenx_ch_inventory = get_livenx_ch_inventory()
                new_livenx_ch_inventory = map_livenx_inventory_to_livenx_ch_inventory(orig_livenx_inventory)
                livenx_ch_inventory_diff_to_add = diff_livenx_ch_inventory(new_livenx_ch_inventory, orig_livenx_ch_inventory)

                if len(livenx_ch_inventory_diff_to_add) > 0:
                    if args.noprompt == True or query_yes_no("This inventory will be added: " + str(livenx_ch_inventory_diff_to_add)):
                        add_to_livenx_ch_inventory(livenx_ch_inventory_diff_to_add)
                else:
                    local_logger.info("ClickHouse device serial is already sync with livenx inventory") 

                ## figure out which devices to remove
                livenx_ch_inventory_diff_to_remove = diff_livenx_ch_inventory(orig_livenx_ch_inventory, new_livenx_ch_inventory)

                if len(livenx_ch_inventory_diff_to_remove) > 0:
                    if args.noprompt == True or query_yes_no("This inventory will be removed: " + str(livenx_ch_inventory_diff_to_remove)):
                        remove_from_livenx_ch_inventory(livenx_ch_inventory_diff_to_remove)
            if args.fromproduct == "bluecat_integrity" and args.toproduct == "livenxch":
                ## sync the Bluecat address to the livenx clickhouse
                ## figure out which sites to add
                orig_bluecat_addresses = get_bluecat_addresses()
                orig_livenxch_inventories = get_livenx_ch_inventory()
                bluecat_addresses_diff_to_add = diff_bluecat_addresses(orig_bluecat_addresses, orig_livenxch_inventories)
                if len(bluecat_addresses_diff_to_add) > 0:
                    if args.noprompt == True or query_yes_no("This inventory will be added: " + str(bluecat_addresses_diff_to_add)):
                        add_to_livenx_ch_inventory(bluecat_addresses_diff_to_add)
                else:
                    local_logger.info("Bluecat addresses is already sync with livenx inventory")  

        elif args.alerts:
            if args.fromproduct == "livenx" and args.toproduct == "servicenow":
                ## Alerts from LiveNX and servicenow sync
                livenx_alerts = get_livenx_alerts(starttimesecs, endtimesecs)
                livenx_alerts = livenx_alerts["alerts"]
                local_logger.info(livenx_alerts)
                servicenow_alerts = get_servicenow_incidents()
                livenx_alerts = {
                '%s' % (livenx_alert.get('alertId')): livenx_alert
                for livenx_alert in livenx_alerts}
                servicenow_alerts = {
                    '%s' % (servicenow_alert.get('number')): servicenow_alert
                for servicenow_alert in servicenow_alerts}
                ### Get alert common in from LiveNX and ServiceNow
                found_livenx_in_servicenow_alerts = {alertId: livenx_alerts[alertId] for alertId in set(livenx_alerts).intersection(set(servicenow_alerts))}
                ### Get alert not exist in ServiceNow
                notfound_livenx_in_servicenow_alerts = {alertId: livenx_alerts[alertId] for alertId in list(set(livenx_alerts) - set(servicenow_alerts))}
                add_livenx_alerts_prompt = [ {
                    'alertId': alertId
                } for alertId in found_livenx_in_servicenow_alerts | notfound_livenx_in_servicenow_alerts]
                if args.noprompt == True or query_yes_no("These alerts will be added: " + str(add_livenx_alerts_prompt)):
                    push_servicenow_incidents(notfound_livenx_in_servicenow_alerts.values())
            elif args.fromproduct == "livenx" and args.toproduct == "livenxch":
                ## sync the LiveNX alerts to the clickhouse alerts
                ## figure out which alerts to add
                orig_livenx_alerts = get_livenx_alerts(starttimesecs, endtimesecs)
                orig_clickhouse_alerts = get_clickhouse_alerts()
                clickhouse_alerts_diff_to_add = diff_clickhouse_alerts(orig_livenx_alerts, orig_clickhouse_alerts)
                if len(clickhouse_alerts_diff_to_add) > 0:
                    if args.noprompt == True or query_yes_no("This alerts will be added: " + str(clickhouse_alerts_diff_to_add)):
                        add_to_clickhouse_alerts(clickhouse_alerts_diff_to_add)
                else:
                    local_logger.info("Clickhouse is already sync with livenx alerts")      
            elif args.fromproduct == "netld":
                alerts = get_netld_incidents()
            
            if args.toproduct == "netld":
                    push_netld_incidents(alerts)
            elif args.toproduct == "livenx":
                    push_livenx_alerts(alerts)

        elif args.sites:
            if args.fromproduct == "bluecat_integrity" and args.toproduct == "livenx":
                ## sync the Bluecat blocks to the livenx sites
                ## figure out which sites to add
                orig_livenx_sites = get_livenx_sites()
                orig_bluecat_sites = get_bluecat_blocks()                
                new_livenx_sites = map_bluecat_blocks_to_livenx_sites(orig_bluecat_sites)
                bluecat_blocks_diff_to_add = diff_bluecat_sites(new_livenx_sites, orig_livenx_sites)
                if len(bluecat_blocks_diff_to_add) > 0:
                    if args.noprompt == True or query_yes_no("This sites will be added: " + str(bluecat_blocks_diff_to_add)):
                        add_to_livenx_sites(bluecat_blocks_diff_to_add)
                else:
                    local_logger.info("Bluecat blocks is already sync with livenx sites")
            elif args.fromproduct == "livenx" and args.toproduct == "livenxch":
                ## sync the Bluecat blocks to the livenx sites
                ## figure out which sites to add
                orig_livenx_sites = get_livenx_sites()
                orig_clickhouse_sites = get_clickhouse_sites()
                clickhouse_sites_diff_to_add = diff_clickhouse_sites(orig_livenx_sites, orig_clickhouse_sites)
                if len(clickhouse_sites_diff_to_add) > 0:
                    if args.noprompt == True or query_yes_no("This sites will be added: " + str(clickhouse_sites_diff_to_add)):
                        add_to_clickhouse_sites(clickhouse_sites_diff_to_add)
                else:
                    local_logger.info("Clickhouse is already sync with livenx sites")

        if args.continuous is False:
            break

        starttimesecs += 60
        endtimesecs += 60
        curtimesecs = get_top_of_current_minute_epoch()
        while (curtimesecs - (60 * (num_minutes_behind+1))) < starttimesecs:
            time.sleep(1)
            curtimesecs = get_top_of_current_minute_epoch()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process LiveNX data.")
    parser.add_argument("--inventory", action="store_true", help="Get and push inventory data.")
    parser.add_argument("--alerts", action="store_true", help="Get and push alerts data.")
    parser.add_argument("--sites", action="store_true", help="Get and push sites data.")
    parser.add_argument('--toproduct', type=str, default='', help='The product to push to')
    parser.add_argument('--fromproduct', type=str, default='', help='The product to push from')
    parser.add_argument('--starttimesecs', type=int, default=0, help='The start time in seconds')
    parser.add_argument('--endtimesecs', type=int, default=0, help='The end time in seconds')
    parser.add_argument('--continuous', action="store_true", help='Run it continuously')
    parser.add_argument('--noprompt', action="store_true", help='Dont prompt')
    parser.add_argument('--logstdout', action="store_true", help='Log to stdout instead of file')
    parser.add_argument('--num_minutes_behind', type=int, default=2, help='The number of minutes to run behind wallclock')
    args = parser.parse_args()
    main(args)
