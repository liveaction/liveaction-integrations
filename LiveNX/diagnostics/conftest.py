def pytest_addoption(parser):
    parser.addoption('--livenx_ip', required=False, help='Specifies liveNX host')
    parser.addoption('--livenx_port', required=False, default='8093', help='liveNx port for API interaction')
    parser.addoption('--livenx_token', required=False, default='', help='liveNx token for API interaction')
