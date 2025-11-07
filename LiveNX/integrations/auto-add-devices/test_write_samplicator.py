import importlib.util
import pathlib

import pytest


MODULE_PATH = pathlib.Path(__file__).with_name("adddevice.py")
MODULE_SPEC = importlib.util.spec_from_file_location("adddevice_module", MODULE_PATH)
adddevice = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(adddevice)


@pytest.mark.parametrize("movedevices", [False, True])
def test_write_samplicator_distributes_subnets_across_nodes(tmp_path, monkeypatch, movedevices):
    config_path = tmp_path / "samplicator.conf"

    existing_inventory = {
        "devices": [
            {"address": "192.168.0.1", "nodeId": "node-1"},
            {"address": "192.168.1.1", "nodeId": "node-2"},
        ]
    }
    livenx_nodes = [
        {"id": "node-1", "ipAddress": "10.0.0.1"},
        {"id": "node-2", "ipAddress": "10.0.0.2"},
    ]

    monkeypatch.setattr(adddevice, "get_livenx_inventory", lambda: existing_inventory)
    monkeypatch.setattr(
        adddevice,
        "get_livenx_nodes",
        lambda include_server=False: [dict(node) for node in livenx_nodes],
    )
    monkeypatch.setattr(adddevice, "add_virtual_device_to_livenx_inventory", lambda devices: None)
    monkeypatch.setattr(adddevice, "move_devices_based_on_subnets", lambda *args, **kwargs: [])

    should_restart = adddevice.write_samplicator_config_to_files(
        set(),
        str(config_path),
        max_subnets=32,
        movedevices=movedevices,
        include_server=False,
    )

    assert should_restart is False
    lines = [line for line in config_path.read_text().splitlines() if line.strip()]
    assert len(lines) == 2
    assigned_targets = {line.split(": ")[1].split("/")[0] for line in lines}
    assert assigned_targets == {"10.0.0.1", "10.0.0.2"}
