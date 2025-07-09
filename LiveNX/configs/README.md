## Best-Practice Flow Configuration Repository

To support our customers, we maintain a repository of best-practice flow configurations based on commonly observed deployments across various vendors. This resource is intended to serve as a helpful reference to accelerate adoption.

Disclaimer: Use of these configurations is at your own risk. We make no guarantees regarding compatibility, performance, or suitability for your specific environment. It is the responsibility of the user to validate and test any configuration before applying it in production. We strongly recommend consulting your vendor’s official documentation to ensure accuracy, compatibility, and supportability for your specific environment.


## LiveNX Config Requirements

LiveNX requires 3 unique templates (1) Traffic (2) Voice, Video, Performance, and (3) Application Response time.  

# Customer Assumptions

These configuration files assume logging into the device via SSH and applying a partial configuration.

Customer will modify interfaces to match their environment.

Customer will modify Class Maps to meter traffic of interest.

The configuration recommendations are created as a guideline.  We strive to keep the documentation updated as it relates to the latest version of software.   Please take caution and apply in a PoC/QA environment first before applying globally within your network.


## Cisco/ASR1000x

The repository contains configs for ISR/ASR1000x series.

## Cisco/Catalyst8k

The repository contains configs for Cisco Catalyst 9k (8300 and 8500) series.

## Cisco/Catalyst9k

The repository contains configs for Cisco Catalyst 9k (9300 and 9500) series.

## Cisco/vEdge2000

The repository contains information for Cisco vEdge 2000 SDWAN configuration.

## Fortigate

The repository contains information for Fortigate firewall configuration.

## Arista

The repository contains information for Arista switch/router configurations.
