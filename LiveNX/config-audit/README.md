### Example
Audit configurations with ChatGPT:
```bash
python config_audit.py.py --devicefile devices.csv --chatgpt
```

Audit configurations without ChatGPT:
```bash
python config_audit.py.py --devicefile devices.csv
```

## How It Works
1. **Device List Parsing:** Reads device information from the specified CSV file.
2. **Configuration Fetch:** Connects to each device via SSH and fetches the running configuration.
3. **Change Detection:** Compares the fetched configuration against the last audited configuration.
4. **Golden Configuration Comparison:** Downloads the golden configuration for the device model and version from GitHub and highlights differences.
5. **ChatGPT Comparison:** Optionally uses ChatGPT to analyze and explain configuration differences.

## Output
- Differences between running and golden configurations are displayed in the terminal.
- Changed configurations are saved to the `configs/` directory with a timestamped filename.
- Audit logs are stored in the SQLite database for future reference.

## Notes
- Ensure the SSH credentials in the CSV file are correct.
- Devices must allow SSH access for the script to function.
- The program assumes golden configurations are structured by model and IOS version in the GitHub repository.

## Usage:
 - Extract the device list from the LiveNX Server using the CSV export at https://x.x.x.x/livenx/settings/device-management?tabId=My%20Devices
 - Open CSV file using a CSV editor and add new empty columns to the end of the column list:
    - Username: should contain the SSH Username used to connect to the device
    - Password: should contain the SSH Password used to connect to the device
    - Golden_File: should be empty, or contain a full path to the golden config file used for comparison. If empty, it will fetch the golden config from github https://raw.githubusercontent.com/liveaction/liveaction-integrations/refs/heads/main/LiveNX/configs/{encoded_model}/{encoded_ios_version}.cfg, which encoded_model is the model name of the device (example: ciscoCSR1000v) and encoded_ios_version is the ios version number (example: 16.3.1).

## License
This program is provided under the MIT License. Use it at your own risk and customize it to fit your requirements.
