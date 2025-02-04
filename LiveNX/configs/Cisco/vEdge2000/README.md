# LiveAction Cflowd Configuration Guide

## Overview
This documentation provides configuration guidelines for LiveAction integration. All recommendations should be tested in a PoC/QA environment before production deployment.

## Device Support Matrix

Legend:
- D: Device Support
- L: LiveNX supports for Device

| MFG/Model | FNF/IPFIX/Cflowd | AVC | MediaNet | NBAR | SFLOW | Proprietary |
|-----------|------------------|-----|-----------|------|-------|-------------|
| Vedge 2000 (Release 17.12.1a+) | DL | - | - | - | - | DL |

## LiveNX Requirements
LiveNX requires 3 unique templates:
1. Traffic
2. Voice, Video, Performance
3. Application Response time

## Customer Assumptions
- SSH access is available for device configuration
- Partial configurations will be applied
- Interfaces will be modified to match customer environment
- Class Maps will be modified to meter traffic of interest

## Flow Configuration Methods
Flow in Vedge can be configured in two ways:
1. Through Vmanage Template
   - Vsmart should be in vmanage mode
2. Through CLI Mode
   - Vsmart should be in cli mode

## Configuration Methods

### 1. Using Vmanage Template

#### Step 1: Start the Policy Configuration Wizard
1. Navigate to Configure > Policies screen
2. Click Add Policy
3. Start with the Create Applications or Groups of Interest screen

#### Step 2: Create Applications or Groups of Interest

##### Prefix Configuration
1. Click Prefix in the left bar
2. Click New Prefix List
3. Enter list name
4. Add data prefixes (comma-separated)
5. Click Add

##### Site Configuration
1. Click Site in the left bar
2. Click New Site List
3. Enter list name
4. Add site IDs (comma-separated)
5. Click Add

##### VPN Configuration
1. Click VPN in the left bar
2. Click New VPN List
3. Enter list name
4. Add VPN IDs (comma-separated)
5. Click Add

#### Step 3: Configure Network Topology
To import existing topology:
1. Select Import Existing Topology
2. Select topology type
3. Choose policy name
4. Click Import

#### Step 4: Configure Traffic Rules
1. Select Cflowd tab under Application-Aware Routing
2. Configure timer parameters:
   - Active Flow Timeout: 60
   - Inactive Flow Timeout: 10
   - Flow Refresh Interval: 60
   - Sampling Interval: 10
3. Configure collector settings:
   - VPN ID
   - IP Address (LiveNX server/Node)
   - Port Number: 2055
   - Transport Protocol: UDP

#### Step 5: Apply Policies
1. Name the policy (alphanumeric, hyphens, underscores only)
2. Add policy description
3. Select policy block type
4. Add site lists
5. Preview policy
6. Save policy

#### Step 6: Activate Policy
1. Navigate to Configure > Policies
2. Select policy
3. Click More Actions > Activate
4. Confirm activation

### 2. Using CLI Mode

#### Basic Configuration Steps

```bash
# Create Site List
policy
lists site-list <site-list-name>
site-id <site-id>
exit

# Create VPN List
policy lists
vpn-list <vpn list name>
vpn <vpn-id>
exit

# Create IP Prefix Lists
policy lists
prefix-list <prefix-list-name>
ip-prefix <prefix/length>
exit

# Configure Cflowd Template
policy cflowd-template LiveAction-Cflowd-template
collector vpn <vpn-id> address <collector-ip> port <port-number> transport-type (transport_tcp | transport_udp) source-interface <interface-name>
flow-active-timeout 60
flow-inactive-timeout 10
protocol <ipv4/ipv6/both>
template-refresh 10
flow-sampling-interval 10
exit

# Create Data Policy
policy data-policy <policy-name>
vpn-list <vpn-list-name>
sequence <sequence-number>
match parameters
action cflowd
exit

# Apply Policies
apply-policy site-list <site-list-name> data-policy <policy-name>
apply-policy site-list <site-list-name> cflowd-template LiveAction-Cflowd-template
write memory
```

## Verification Commands
```bash
show policy
show cflowd statistics
show cflowd cache
```