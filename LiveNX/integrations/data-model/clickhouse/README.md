# Installation

On all nodes and servers:

cd liveaction-integrations/LiveNX/integrations/data-model/clickhouse

sh ./create_db.sh

## To Enable Local LiveAssist and OTEL Collection

sh ./create_liveassist_tables_1.0.sh

Add clickhouse to the OTEL collector export:

```
exporters:
  clickhouse:
    async_insert: true
    compress: lz4
    create_schema: true
    endpoint: tcp://127.0.0.1:9440?dial_timeout=10s&secure=true&skip_verify=true
    password: xxxx
    retry_on_failure:
      enabled: true
      initial_interval: 5s
      max_elapsed_time: 300s
      max_interval: 30s
    timeout: 5s
    ttl: 72h
    username: default
```

Add clickhouse exporter to the service pipelines

```
service:
...
  pipelines:
    logs:
      exporters:
      - clickhouse
...
    metrics:
      exporters:
      - clickhouse
...
    traces:
      exporters:
      - clickhouse
...
```

Open TCP reports for the OTEL collector:

```
sudo iptables -A INPUT -p tcp --dport 4317 -j ACCEPT 
sudo iptables -A INPUT -p tcp --dport 4318 -j ACCEPT 
```


## To Run The Data Model Sync

Edit the run_model_sync.sh script to set the environment variables to the proper settings. Typically only the CLICKHOUSE_PASSWORD and LIVENX_API_TOKEN environment variables need to be set.

Run the sync via:

sh ./run_model_sync.sh

Stop the sync via:

sh ./stop_model_sync.sh