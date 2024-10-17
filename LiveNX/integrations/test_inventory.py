
import pytest
from common.livenx_inventory import get_livenx_inventory
from netld.inventory import add_to_netld_inventory
from helper.timer import get_top_of_current_minute_epoch
import logging
local_logger = logging.getLogger(__name__)

@pytest.fixture(scope="module")
def investory_holder():
    return {}

def test_get_livenx_inventory():
    '''
    test include to check the response for livenx inventory api call
    '''
    num_minutes_behind = 2
    starttimesecs = get_top_of_current_minute_epoch() - (60 * (num_minutes_behind + 1))
    endtimesecs = get_top_of_current_minute_epoch() - (60 * num_minutes_behind)
    inventory = get_livenx_inventory(starttimesecs, endtimesecs)
    investory_holder = inventory
    assert type(inventory) == dict

def test_push_netld_inventory(investory_holder):
    inventory_keys = list(investory_holder.keys())
    inventory = {address:investory_holder[address] for address in inventory_keys}
    try:
        add_to_netld_inventory(inventory)
        assert 1 == 1
    except Exception as err:
        local_logger.info(f"Error while pushing investory from LiveNx to NetLd {err}")
        assert 1 == 0
    