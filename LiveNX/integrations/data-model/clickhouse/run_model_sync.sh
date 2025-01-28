#!/bin/bash

export LIVENX_API_HOST=127.0.0.1
export LIVENX_API_PORT=8093
export LIVENX_API_TOKEN="foobar"
export LIVENX_TARGET_IP=127.0.0.1
export CLICKHOUSE_HOST=127.0.0.1
export CLICKHOUSE_USERNAME=default
export CLICKHOUSE_PASSWORD=foobar2
export CLICKHOUSE_PORT=9440
export CLICKHOUSE_CERTFILE=/etc/clickhouse-server/cacerts/ca.crt
export CLICKHOUSE_KEYFILE=/etc/clickhouse-server/cacerts/ca.key

# Run the Python scripts in background
python3 ../main.py --inventory --fromproduct livenx --toproduct livenxch --noprompt --continuous &
# Store the PIDs for each background process
echo "Started inventory process with PID: $!"
inventory_pid=$!
python3 ../main.py --sites --fromproduct livenx --toproduct livenxch --noprompt --continuous &
echo "Started sites process with PID: $!"
sites_pid=$!
python3 ../main.py --alerts --fromproduct livenx --toproduct livenxch --noprompt --continuous &
echo "Started alerts process with PID: $!"
alerts_pid=$!

# Optional: Write PIDs to a file for later management
echo "$inventory_pid $sites_pid $alerts_pid" > integration_pids.txt

echo "All processes started in background. PIDs saved to integration_pids.txt"