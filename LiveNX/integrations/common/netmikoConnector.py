from netmiko import ConnectHandler


def fetch_running_config(device):
    try:
        connection = ConnectHandler(**device)
        running_config = connection.send_command("show ip interface brief")
        connection.disconnect()
        return running_config
    except Exception as e:
        print(f"Error fetching running config for device {device['host']}: {e}")
        return None