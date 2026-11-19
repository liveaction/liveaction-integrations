from unittest.mock import patch

from vmanage import inventory as vm

VMANAGE_DEVICES = [
    {"system-ip": "10.0.0.1", "host-name": "vedge-1", "device-type": "vedge", "device-model": "vedge-cloud",
     "version": "20.9.3", "board-serial": "SN1", "site-id": "100", "reachability": "reachable"},
    {"system-ip": "10.0.0.2", "host-name": "vedge-2", "device-type": "vedge", "site-id": "200",
     "reachability": "unreachable"},
    {"system-ip": "10.0.0.9", "host-name": "vsmart-1", "device-type": "vsmart", "reachability": "reachable"},
    {"host-name": "no-ip", "device-type": "vedge"},
]


def _map(**overrides):
    with patch.object(vm, "get_livenx_nodes", return_value=[{"id": "node-1", "ipAddress": "1.2.3.4"}]), \
         patch.object(vm, "liveNxTargetIP", "1.2.3.4"):
        for key, value in overrides.items():
            patch.object(vm, key, value).start()
        try:
            return vm.map_vmanage_inventory_to_livenx_inventory(VMANAGE_DEVICES)
        finally:
            patch.stopall()


def test_map_filters_to_edges_with_ip():
    devices = _map()["devices"]
    assert [d["hostName"] for d in devices] == ["vedge-1", "vedge-2"]
    first = devices[0]
    assert first["nodeId"] == "node-1"
    assert first["address"] == "10.0.0.1"
    assert first["site"] == "SDWAN-Site-100"
    assert "vedge-cloud" in first["systemDescription"] and "SN1" in first["systemDescription"]
    assert first["interfaces"][0]["address"] == "10.0.0.1"


def test_map_only_reachable_and_forced_site():
    devices = _map(vmanageOnlyReachable=True, vmanageLivenxSite="HQ")["devices"]
    assert [d["hostName"] for d in devices] == ["vedge-1"]
    assert devices[0]["site"] == "HQ"


def test_map_fails_without_matching_node():
    with patch.object(vm, "get_livenx_nodes", return_value=[{"id": "x", "ipAddress": "other"}]), \
         patch.object(vm, "liveNxTargetIP", "1.2.3.4"):
        try:
            vm.map_vmanage_inventory_to_livenx_inventory(VMANAGE_DEVICES)
            assert False, "expected RuntimeError"
        except RuntimeError:
            pass


def test_diff_skips_devices_already_in_livenx():
    new = _map()
    existing = {"devices": [{"hostName": "vedge-1", "address": "10.0.0.1"}]}
    diff = vm.diff_vmanage_inventory(new, existing)
    assert [d["hostName"] for d in diff] == ["vedge-2"]
