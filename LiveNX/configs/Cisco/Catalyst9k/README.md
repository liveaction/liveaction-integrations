## These are recommended configs for Cisco Catalyst 9k devices

## The configuration recommendations are created as a guideline.  We strive to keep the documentation updated as it relates to the latest version of software.   Please take caution and apply in a PoC/QA environment first before applying globally within your network.

Models: 9300, 9500

## LiveNX Requirements##
LiveNX requires 3 unique templates (1) Traffic (2) Voice, Video, Performance, and (3) Application Response time. 

## Customer Assumptions

These configuration files assume logging to the device via SSH and applying a partial configuration.

Customer will modify interfaces to match their environment.

Customer will modify Class Maps to meter traffic of interest.

## Limitations Related to these models
Management interface cannot be used as Flow source.

Switch Trunk port cannot be used as Flow source.

NBAR cannot be configured on VLAN interface. 

NBAR and FNF can not be used on same interface.




