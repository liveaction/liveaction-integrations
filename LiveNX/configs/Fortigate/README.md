# Fortigate Firewall Netflow Configuration

## Netflow/sFlow

The FortiGate supports both Netflow and sFlow. Important considerations:
- sFlow is handled by the CPU
- Netflow is handled by the ASIC (if the device has it)
- Netflow is preferred and suggested with LiveNX as this has a lesser impact on the overall performance of the FortiGate
- On the Fortigate, Netflow works on L3 interfaces
- From version 7.x, Netflow can also be enabled on IPSEC interfaces
- Netflow needs to be configured from the CLI

### Basic Configuration

```
config system netflow
    set collector-ip 10.255.0.251 # LiveNX Server/node
    set source-ip 10.255.0.71     # Management IP of the Fortigate
    set template-tx-timeout 600    # optional
    set template-tx-counter 540    # optional
end

config system interface
    edit "port2"
    set netflow-sampler both      # 'in' or 'out' is also possible here
    next
end
```

## Application Detection

By default, FortiGate will send basic NetFlow to LiveNX and based on the firewall policies it will also send application IDs. If a policy does not have application control enabled, the FortiGate will not send the application ID in the flow information. Therefore, it is advised to enable Application Control on all firewall policies to have greater visualization on applications.

## VDOM (Virtual Domains)

When using VDOMs (virtual domains aka virtual firewalls), Netflow uses the management VDOM (root) to route to LiveNX.

### Global VDOM Configuration

Configure Netflow for the entire system:

```
config global
    config system netflow
        set collector-ip 10.255.0.251
        set source-ip 10.255.0.71
        set template-tx-timeout 600    # optional
        set template-tx-counter 540    # optional
    end

    config system interface
        edit "port2"
        set netflow-sampler both      # 'in' or 'out' is also possible here
        next
    end
```

### Per-VDOM Configuration

To send Netflow per VDOM (override Global config):

```
config vdom
    edit secondvdom
    config system vdom-netflow
        set vdom-netflow enable
        set collector-ip 10.255.0.251
        set source-ip 10.255.11.71
    end
```

> **Note:** LiveNX needs to be configured to receive flows from this specific VDOM, as a separate device in LiveNX, Non-SNMP device or using "Associate Probe at IP Address". The source IP of the flow needs to originate from the VDOM.