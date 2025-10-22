# Inserting recommended and running router configs into LiveNX so LiveAssist can analyze them

## Example of adding a running router config

./insert_config.sh --file ASAv-FW-config.txt --router-name ASAv-FW --router-ip 10.255.255.4  --vendor cisco --severity info --database default --table otel_logs --docker-container clickhouse-server

## Example of adding a recommended router config

./insert_config.sh --file ciscoCatalyst8k_recommended.txt --router-name ciscoCatalyst8k --router-ip 10.255.255.10  --vendor cisco --severity info --database default --table otel_logs --docker-container clickhouse-server --service-name recommendrouterconfig
