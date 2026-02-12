## Platform: N9K-C93360YC-FX2 | NX-OS 9.3(x)

The Nexus 9300-FX2 supports NetFlow as of NX-OS 7.0(3)I7(3).

**Important platform notes:**
- On FX2, SVI NetFlow captures **routed traffic only**
- On FX2, VLAN (bridged) NetFlow captures **switched traffic only**
- To get full visibility, apply **both** SVI and VLAN monitors per VLAN
- The SVI monitor and VLAN monitor **must use different flow monitor names**
  (Cisco requires separate monitors for VLAN vs L3 interfaces)
- `ing-netflow` TCAM is pre-allocated at 512 entries — no carving needed

### 1. AVC (Application Visibility and Control)
AVC is not supported on NX-OS /Nexus 9000
See Below.
https://www.cisco.com/c/en/us/td/docs/ios/solutions_docs/avc/guide/avc-user-guide/avc_supported_interfaces.html |

### 2. NBAR / NBAR2 (Network-Based Application Recognition)

NBAR / NBAR2 NOT SUPPORTED on NX-OS / Nexus 9000 
NBAR/NBAR2 is the DPI engine underlying AVC. It is an IOS/IOS XE-exclusive feature. The Cisco Feature Navigator confirms NBAR is not available on any Nexus platform. The Nexus 9000 NX-OS configuration guides contain zero references to NBAR or NBAR2 commands.
See Below
https://www.cisco.com/c/en/us/td/docs/ios/solutions_docs/avc/guide/avc-user-guide/avc_supported_interfaces.html 

### 3. Medianet Performance Monitor / Mediatrace

Medianet NOT SUPPORTED on NX-OS / Nexus 9000
Medianet Performance Monitor and Mediatrace are IOS XE-exclusive features designed for WAN/branch router environments. They rely on IOS XE Flexible NetFlow with AVC/NBAR for application-level media monitoring. No Nexus platform supports these features. The NX-OS NetFlow implementation uses its own dual-layer hardware architecture unrelated to Medianet.
See Below
 https://www.cisco.com/c/en/us/td/docs/ios/solutions_docs/avc/guide/avc-user-guide/avc_tech_overview.html

 ### 4. Flexible NetFlow (Hardware-Based)
 Supported. The Nexus 9000 supports Flexible NetFlow with a hardware-based dual-layer architecture: the first layer processes and aggregates packets at line rate; the second layer maintains hundreds of thousands of flows and periodically exports them. The N9K-C93360YC-FX2 uses the LS 3600 FX2 CloudScale ASIC, which is a 9300-FX2 family member explicitly listed as supported. NetFlow support for the 93360YC-FX2 was introduced beginning with NX-OS 9.3(5) per release notes. Version 9 export format is supported (Version 5 is NOT).
 See Below
 https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/104x/config-guides/cisco-nexus-9000-series-nx-os-system-management-configuration-guide-release-104x/m-configuring-netflow-104x.html

 ### 5. sFlow
 Supported. sFlow is supported on Nexus 9300-FX2 platform switches. Notably, starting with the FX2 family, sFlow and SPAN can coexist simultaneously (earlier EX/FX could not). sFlow is a sampled-packet technology distinct from NetFlow's flow-based approach. Both can be enabled, but not both sFlow and NetFlow on the same interface simultaneously.
 See Below
  https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/104x/config-guides/cisco-nexus-9000-series-nx-os-system-management-configuration-guide-release-104x/m-configuring-sflow.html

  match ip tos
  **Non-functional on all Nexus 9000.** Cisco docs (every release 7.x–10.5.x) state: *"The match ip tos command is present in flow record configuration options, but the functionality is not supported."* The CLI accepts it without error, but the CloudScale ASIC never populates the field. Flows will show ToS as 0x0. |
 match output interface 
**Always returns 0x0 on FX2 at NX-OS 9.3(x).** Output interface (output_if_id) support for the 9300-FX2 was only added in NX-OS 10.3(3)F. On 9.3(11), the ASIC does not populate this field — every flow will report output interface as 0x0. If you upgrade to 10.3(3)F or later, you can add this back.

