from clickhouse_driver import Client
import ssl
import logging
local_logger = logging.getLogger(__name__)

def connect_with_tls(host, port, user, password, database, ca_certs='/path/to/ca.pem', certfile='/etc/clickhouse-server/cacerts/ca.crt', keyfile='/etc/clickhouse-server/cacerts/ca.key'):


    # TLS configuration
    tls_params = {
        "secure": True,                  # Enable TLS
        "verify": False,                  # Verify server's certificate
        "ssl_version": ssl.PROTOCOL_SSLv23,        # Optional: Set specific TLS version (e.g., TLSv1.2)
        "ca_certs": ca_certs,   # Optional: Path to CA certificate file
        "certfile": certfile, # Optional: Path to client certificate file
        "keyfile": keyfile,   # Optional: Path to client private key file
    }

    try:
        # Establish the connection
        client = Client(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            secure=tls_params["secure"],
            verify=tls_params["verify"],
            ssl_version=tls_params.get("ssl_version"),
            # ca_certs=tls_params.get("ca_certs"),
            certfile=tls_params.get("certfile"),
            keyfile=tls_params.get("keyfile"),
        )
        local_logger.info("Connected to ClickHouse with TLS successfully!")
        return client

    except Exception as e:
        local_logger.error(f"Error connecting to ClickHouse: {e}")
        return None

