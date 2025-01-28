# Installation of New Data Model

On LiveNX Server Only:

cd liveaction-integrations/LiveNX/integrations/data-model/clickhouse

sh ./create_db.sh

## To Run The Data Model Sync

Install the integration libraries:

cd liveaction-integrations/LiveNX/integrations

sudo apt install pip

pip3 install -r requirements.txt 

Only on the LiveNX Server, run the sync via:

cd liveaction-integrations/LiveNX/integrations/data-model/clickhouse

Edit the run_model_sync.sh script to set the environment variables to the proper settings. Typically only the CLICKHOUSE_PASSWORD and LIVENX_API_TOKEN environment variables need to be set. The CLICKHOUSE_PASSWORD value can be found in the /etc/clickhouse-server/users.d/users.xml file. The LIVENX_API_TOKEN can be found in the LiveNX WebUI at the location: https://x.x.x.x/api-token

Run the sync via:

sh ./run_model_sync.sh

Stop the sync via:

sh ./stop_model_sync.sh

## Viewing the new Data Model

Information from the new data model can be viewed by installing the Grafana dashboards found in the liveaction-integrations/LiveNX/grafana/data-model diretory.

## To Integrate LiveAssist and OTEL Collection with the New Data Model

On the LiveNX Server only:

sh ./create_liveassist_tables_1.0.sh

Add clickhouse to the OTEL collector export in /etc/la-otelcol.yaml:

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

Add clickhouse exporter to the service pipelines in /etc/la-otelcol.yaml:

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

Add the setting in in /etc/la-otelcol.yaml to send the infrastructure data from the new data model to the OTEL endpoint:

```
receivers:
  liveaction:
    ...
    send_infrastructure: true
    ...
```

Open TCP ports for the OTEL collector:

```
sudo iptables -A INPUT -p tcp --dport 4317 -j ACCEPT 
sudo iptables -A INPUT -p tcp --dport 4318 -j ACCEPT 
```

