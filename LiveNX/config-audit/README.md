### Example
Audit configurations with ChatGPT:
```bash
python audit_tool.py --devicefile devices.csv --chatgpt
```

Audit configurations without ChatGPT:
```bash
python audit_tool.py --devicefile devices.csv
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

## License
This program is provided under the MIT License. Use it at your own risk and customize it to fit your requirements.