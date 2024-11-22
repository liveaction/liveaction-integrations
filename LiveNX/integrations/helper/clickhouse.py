from clickhouse_driver import Client

def connect_with_tls(host, port, user, password, database):


    # TLS configuration
    tls_params = {
        "secure": True,                  # Enable TLS
        "verify": False,                  # Verify server's certificate
        "ssl_version": "TLSv1_2",        # Optional: Set specific TLS version (e.g., TLSv1.2)
        "ca_certs": "/path/to/ca.pem",   # Optional: Path to CA certificate file
        "certfile": "/path/to/cert.pem", # Optional: Path to client certificate file
        "keyfile": "/path/to/key.pem",   # Optional: Path to client private key file
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
            ca_certs=tls_params.get("ca_certs"),
            certfile=tls_params.get("certfile"),
            keyfile=tls_params.get("keyfile"),
        )
        
        print("Connected to ClickHouse with TLS successfully!")
        return client

    except Exception as e:
        print(f"Error connecting to ClickHouse: {e}")
        return None

