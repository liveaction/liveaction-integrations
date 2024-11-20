#!/bin/bash

# Enable strict error handling
set -e 

# Execute the ClickHouse commands
docker exec -i clickhouse-server clickhouse-client -n <<-EOSQL

DROP TABLE IF EXISTS livenx_flowdb.basic_entity_1m_stream;
DROP TABLE IF EXISTS livenx_flowdb.basic_entity_1m_stream_mv;

EOSQL
