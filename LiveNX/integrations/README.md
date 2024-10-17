# LiveNX-Integrations

This repository contains the integrations from LiveAction's LiveNX to third party platforms.

The following third party platforms are currently supported:

LogicVein NetLD/ThirdEye
----------------

    Operations Supported: 
    ---------------------
        + Push LiveNX devices to NetLD inventory 
        + Push NetLD devices to LiveNX inventory


Building Docker Image
---------------------

docker build -t liveaction/livenx-integrations .

Running Docker Image
--------------------

docker run -e LIVENX_API_HOST=10.0.0.1 -e LIVENX_API_PORT=8093 -e LIVENX_API_TOKEN=your_token_here -e THIRDEYE_API_HOST=10.100.155.150 -e THIRDEYE_API_USER=netlduser -e THIRDEYE_API_PASSWORD="netldpass" -e THIRDEYE_NETWORK=Default your_image_name --inventory --fromproduct livenx --toproduct netld --continuous

Examples:
---------


netLD
-----

From the command line
---------------------

To run the following examples these environment variables must be set (example):

LIVENX_API_HOST=10.4.205.201
LIVENX_API_PORT=8093
LIVENX_API_TOKEN="foobar"
THIRDEYE_API_HOST=10.100.155.150
THIRDEYE_API_USER=netlduser
THIRDEYE_API_PASSWORD="netldpass"
THIRDEYE_NETWORK=Default


Push inventory continuously from LiveAction LiveNX to LogicVein NetLD:

python3 main.py --inventory --fromproduct livenx --toproduct netld --continuous


Push all current inventory from LogicVein NetLD to LiveAction LiveNX:

python3 main.py --inventory --fromproduct netld --toproduct livenx

Using Docker Run
----------------

docker run -e LIVENX_API_HOST=10.0.0.1 -e LIVENX_API_PORT=8093 -e LIVENX_API_TOKEN=your_token_here -e THIRDEYE_API_HOST=10.100.155.150 -e THIRDEYE_API_USER=netlduser -e THIRDEYE_API_PASSWORD="netldpass" -e THIRDEYE_NETWORK=Default liveaction/LiveNX-Integrations --inventory --fromproduct livenx --toproduct netld --continuous

Using Docker Compose
--------------------

Edit the docker-compose.yml with the nescessary parameters.

then execute:

docker compose up -d


| LiveWire Product | External Product | Attribute in LiveNX | Attribute in External Product |
| ---------------- | ---------------- | ------------------- | ----------------------------- |
| LiveNX | LiveNCA/NetLD | hostName | hostname |
| LiveNX | LiveNCA/NetLD | network | network |
| LiveNX | LiveNCA/NetLD | hostName | hostname |
| LiveNX | LiveNCA/NetLD | address | ipAddress |
| LiveNX | LiveNCA/NetLD | vendorProduct>displayName | adapterId |
| LiveNX | LiveNCA/NetLD | vendorProduct>displayName | softwareVendor |
| LiveNX | LiveNCA/NetLD | osVersionString | osVersion |
| LiveNX | LiveNCA/NetLD | serialNumber | serialNumber |
