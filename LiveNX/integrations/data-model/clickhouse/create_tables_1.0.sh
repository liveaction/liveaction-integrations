#!/bin/bash
set -e
docker exec -i clickhouse-server clickhouse-client -n <<-EOSQL

CREATE DATABASE IF NOT EXISTS inventory_db;
CREATE TABLE IF NOT EXISTS inventory_db.Device_Inventory
(
    -- Core Fields
    Href String,
    ID String,
    Type String,
    Name String,
    Serial String,
    Client_IP String,
    System_Name String,
    Display_System_Name String,
    Host_Name String,
    Display_Host_Name String,
    System_Location String,
    System_Description String,
    
    -- OS Version
    OS_Version Nested(
        Major_Number UInt16,
        Minor_Number UInt16,
        Indiv_Number Nullable(UInt16),
        Indiv_Number_Suffix Nullable(String),
        New_Feature_Identifier Nullable(String),
        New_Feature_Version Nullable(String),
        Version_String Nullable(String),
        OS_Type String
    ),
    OS_Version_String String,
    
    -- Vendor Product
    Vendor_Product Nested(
        Model String,
        Display_Name String,
        Description String,
        Vendor Nested(
            Vendor_Name String,
            Vendor_OID Nullable(String),
            Vendor_Serial_OID Nullable(String)
        ),
        Object_OID Nullable(String),
        Object_OID_String Nullable(String),
        ASR_Model Bool
    ),
    
    -- User-Defined Fields
    User_Defined_Fields Nested(
        Key String,
        Value String
    ),
    
    -- Configuration
    Configuration Nested(
        ID String,
        Type String,
        Name String
    ),
    
    -- MAC Address
    MAC_Address Nested(
        ID String,
        Type String,
        Name String,
        Address String
    ),
    
    -- Device Information
    Device Nested(
        ID String,
        Type String,
        Name String
    ),
    
    -- Location
    Location Nested(
        ID String,
        Type String,
        Name String
    ),
    
    -- Lease Information
    Lease_Date_Time DateTime,
    Lease_Expiration_Date_Time DateTime,
    Remote_ID String,
    
    -- IP Group and Template
    IP_Group Nested(
        ID String,
        Type String,
        Name String
    ),
    Template Nested(
        ID String,
        Type String,
        Name String
    ),
    
    -- Misc Fields
    Site String,
    Is_Data_Center_Site Bool,
    Tags Array(String),
    Tagged_Omni Bool,
    
    -- Interfaces
    Interfaces Nested(
        Name String,
        Abbreviated_Name String,
        If_Index UInt16,
        Description Nullable(String),
        Speed UInt64,
        Type String,
        WAN Bool,
        XCON Bool,
        Interface_State String
    ),
    
    -- Monitor and Settings
    Monitor_Only Bool,
    Settings Nested(
        Poll_Interval UInt64,
        Enable_Poll Bool,
        Enable_QoS_Poll Bool,
        Enable_Netflow_Poll Bool,
        Enable_IPSLA_Poll Bool,
        Enable_LAN_Poll Bool,
        Enable_Routing_Poll Bool,
        Virtual_Device Bool
    ),
    
    -- Capabilities
    Capabilities Nested(
        NBAR_Capable Bool,
        Netflow_Collector_Capable Bool,
        MediaTrace_Capable Bool,
        Extended_Trace_Route_Capable Bool,
        NBAR2_Capable Bool,
        Flexible_Netflow_Capable Bool,
        Perfmon_Capable Bool,
        AVC_Capable Bool,
        Unified_Perfmon_Capable Bool,
        HQF_Support_Detected Bool,
        IPSLA_Capable Bool
    ),
    
    -- Polling Support
    Polling_Supported Nested(
        Netflow_Polling_Supported Bool,
        IPSLA_Polling_Supported Bool,
        LAN_Polling_Supported Bool,
        Routing_Polling_Supported Bool,
        QoS_Polling_Supported Bool
    ),
    
    -- Circuit and Port Information
    Circuit_ID String,
    Router_Port_Info String,
    Switch_Port_Info String,
    VLAN_Info String,
    Vendor_Class_Identifier String,
    
    -- Parameter Request List
    Parameter_Request_List Array(UInt16),
    
    -- Client Identifier
    Client_Identifier Nested(
        ID String,
        Type String,
        Name String,
        UID Nested(
            Client_Identifier String
        ),
        DUID Nullable(String)
    ),
    
    -- IPv6 Specific Fields
    Reserved_Using Nullable(String),
    Identity_Association_Identifier Nullable(String),
    Interface_ID Nullable(String),
    
    -- Links
    _Links Nested(
        Self_Href String,
        Collection_Href String
    ),
    
    -- Group and Link Info
    Group_ID String,
    Link_Info Nested(
        Type String,
        Label String,
        Display_Value String,
        Raw_Value Nested(
            Name String,
            Host String,
            Path String,
            Start_Time DateTime,
            End_Time DateTime,
            Show_Dialog Bool
        )
    ),
    
    -- Additional Metadata
    Analytics_Node String,
    State String,
    User_Defined_Sample_Ratio UInt32,
    Device_Loaded_State String
)
ENGINE = ReplacingMergeTree()
PRIMARY KEY (ID)
ORDER BY (ID, Type)
SETTINGS index_granularity = 8192;


CREATE TABLE IF NOT EXISTS inventory_db.Network_Sites
(
    -- Core Site Information
    ID UUID,                               -- Unique identifier for the site.
    Site_Name String,                      -- Name of the site.
    Site_Description String,               -- Description of the site.
    Type String,                           -- Type of site (e.g., "building").
    Is_Data_Center Bool,                   -- Indicates if the site is a data center.
    Site_IP_Ranges Array(String),          -- List of IP ranges associated with the site.
    Is_Configured Bool,                    -- Indicates if the site is configured.

    -- Mailing Address
    Mailing_Address Nested(
        Address1 String,                     -- Primary address line.
        Address2 Nullable(String),           -- Secondary address line.
        City String,                         -- City name.
        State String,                        -- State or province.
        ZIP String,                          -- Postal code.
        Country String                       -- Country name.
    ),

    -- Geographical Position
    Position Nested(
        Latitude Float64,                    -- Latitude of the site.
        Longitude Float64                    -- Longitude of the site.
    ),

    -- Regional Information
    Region Nested(
        ID UUID,                             -- Unique identifier for the region.
        Long_Name String,                    -- Full name of the region (e.g., "California").
        Short_Name String,                   -- Abbreviation of the region (e.g., "CA").
        Type String,                         -- Type of region (e.g., "STATE").
        Parent Nullable(String)              -- Parent region identifier.
    ),

    -- Location Details [NEW]
    Location Nested(
        ID UInt64,                           -- Unique identifier for the location.
        Type String,                         -- Type of location (e.g., "Location").
        Name String,                         -- Name of the location.
        Locode String,                       -- Standardized location code (e.g., "JP TYO").
        Code String,                         -- Full location code (e.g., "JP TYO BCN").
        Country String,                      -- Country code (e.g., "JP").
        Description String,                  -- Description of the location.
        Localized_Name String,               -- Localized name of the location.
        Subdivision String,                  -- Subdivision code (e.g., region or state).
        Longitude Float64,                   -- Longitude of the location.
        Latitude Float64                     -- Latitude of the location.
    ),
    User_Defined_Fields Nested(           -- User-defined fields for the location. [NEW]
        Key String,
        Value String
    ),

    -- Contact Information
    Contact_Name String,                   -- Name of the contact person for the site.
    Phone_Number String,                   -- Phone number for the site contact.
    Email String,                          -- Email address for the site contact.

    -- Site Details
    Number_Of_Employees UInt32,            -- Number of employees at the site.
    Tier_Category_ID UUID,                -- Identifier for the site's tier category.

    -- Devices
    Devices Nested(
        Device_Serial String,                -- Serial number of the device.
        Device_Name String,                  -- Name of the device.
        Host_Name String,                    -- Hostname of the device.
        WAN Bool,                            -- Indicates if the device is connected to a WAN.
        Tagged_Omni Bool                     -- Indicates if the device is tagged for Omni usage.
    ),

    -- Business Hours
    Business_Hours Nested(
        Site String,                         -- Name of the site.
        ID UUID,                             -- Unique identifier for the business hours record.
        Time_Settings Nested(
            Days Array(String),              -- Days the site operates (e.g., ["monday", "tuesday"]).
            Start_Time String,               -- Business start time (HH:mm format).
            End_Time String,                 -- Business end time (HH:mm format).
            Enable_DST Bool,                  -- Indicates if Daylight Savings Time is enabled.
            Time_Zone Nested(
                Display_Value String,        -- Display name of the time zone.
                Raw_Value String             -- Raw time zone identifier.
            )
        )
    ),

    -- Client Messages
    Client_Messages Array(String),         -- Messages from clients or systems about the site.

    -- Tags
    Tags Array(String)                     -- Tags associated with the site.
)
ENGINE = ReplacingMergeTree()
PRIMARY KEY (ID)
ORDER BY (ID)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS inventory_db.SDWAN_Inventory
(
    ID String,
    Device_Name String,
    Device_Type String,
    Serial_Number String,
    Management_IP String,
    Site String,
    Location String,
    OS_Version String,
    Links Nested(
        Link_ID String,
        Source_Node String,
        Destination_Node String,
        Bandwidth UInt32,
        Latency Float32,
        Jitter Float32,
        Packet_Loss Float32
    ),
    Interfaces Nested(
        Interface_Name String,
        Interface_Type String,
        Status String,
        Bandwidth UInt32,
        Traffic_In UInt64,
        Traffic_Out UInt64,
        Errors UInt32
    ),
    Policies Nested(
        Policy_Name String,
        Source_IP String,
        Destination_IP String,
        Traffic_Type String,
        Priority UInt8
    ),
    Last_Updated DateTime
)
ENGINE = ReplacingMergeTree()
PRIMARY KEY (ID)
ORDER BY (ID)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS inventory_db.SNMP_Inventory
(
    -- Device Information
    ID String,                           -- Unique identifier for the device
    Device_Name String,                  -- Name of the device
    Device_Type String,                  -- Type/category of the device
    Management_IP String,                -- Management IP address for SNMP
    Site String,                         -- Location of the device
    Vendor String,                       -- Device manufacturer
    Model String,                        -- Device model

    -- SNMP Metrics
    SNMP_Metrics Nested(
        Metric_Name String,                -- Name of the metric
        OID String,                        -- SNMP OID for the metric
        Value Float64,                     -- Metric value
        Unit String,                       -- Unit of measurement
        Timestamp DateTime                 -- Metric collection time
    ),

    -- SNMP Traps
    SNMP_Traps Nested(
        Trap_ID String,                    -- Unique identifier for the trap
        Trap_Type String,                  -- Type of trap
        Trap_Source String,                -- Source device of the trap
        Trap_OID String,                   -- OID associated with the trap
        Severity String,                   -- Severity level of the trap
        Timestamp DateTime                 -- Trap reception time
    ),

    -- SNMP Interfaces
    SNMP_Interfaces Nested(
        Interface_Name String,             -- Name of the interface
        If_Index UInt16,                   -- Interface SNMP index
        Status String,                     -- Interface status (UP/DOWN)
        Traffic_In UInt64,                 -- Incoming traffic in bytes
        Traffic_Out UInt64,                -- Outgoing traffic in bytes
        Errors UInt32,                     -- Number of errors
        Timestamp DateTime                 -- Last update time for the interface
    ),

    -- SNMP Configuration
    SNMP_Configuration Nested(
        Community_String String,           -- Community string for SNMP
        Version String,                    -- SNMP version (v1, v2c, v3)
        Security_Level String,             -- SNMPv3 security level
        Username Nullable(String),         -- SNMPv3 username
        Auth_Protocol Nullable(String),    -- Authentication protocol (SNMPv3)
        Priv_Protocol Nullable(String),    -- Privacy protocol (SNMPv3)
        Timestamp DateTime                 -- Configuration update time
    ),

    -- Polling Configuration
    Polling_Configuration Nested(
        Poll_Interval UInt32,              -- Polling interval in seconds
        Retries UInt8,                     -- Number of retries
        Timeout UInt16,                    -- Timeout in milliseconds
        Last_Polled DateTime               -- Timestamp of last successful poll
    )
)
ENGINE = ReplacingMergeTree()
PRIMARY KEY (ID)
ORDER BY (ID, Device_Type)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS inventory_db.Alert_Inventory
(
    -- Basic Alert Metadata
    Version String,
    Alert_Id String,
    Type String,
    Alert_Category String,
    Alert_Identifier_Id String,
    Date_Created DateTime,
    Date_Closed Nullable(DateTime),
    Duration_Since_Created_Minutes Int32,
    Duration_Active_Minutes Int32,
    Severity String,
    User_Status String,
    Contributes_To_Status Bool,
    Alert_State String,
    Date_Of_Last_Alert_State_Change Nullable(DateTime),

    -- Alert Description
    Description_Title String,
    Description_Summary String,
    Description_Details Array(Tuple(String, String, String)),
    Description_Source_Info Array(Tuple(String, String, String, Nullable(String))),
    Description_Link_Info Array(Tuple(String, String, String, Nullable(String))),
    Description_Table_Info_Label String,
    Description_Table_Info_Columns Array(Tuple(String, String, String)),
    Description_Table_Info_Rows Array(Array(Tuple(String, String, String))),

    -- Root Cause Analysis
    Root_Cause_Analysis_Summary String,
    Root_Cause_Analysis_Issues Array(Tuple(String, String)),
    Root_Cause_Analysis_Chain_Id String,

    -- Alert Integrations
    Alert_Integrations_ServiceNow_Alert_Integration_Incident_Number String,
    Alert_Integrations_ServiceNow_Alert_Integration_Incident_Url String
)
ENGINE = MergeTree
-- Replace nullable columns in the sorting key with coalesced values
ORDER BY (Alert_Id, Type, COALESCE(Date_Created, toDateTime('1970-01-01 00:00:00')), COALESCE(Date_Closed, toDateTime('1970-01-01 00:00:00')))
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS inventory_db.Audit_Log (
    Id UInt32,
    Name String,
    Device_Type String,
    Device_Serial String,
    Host String,
    Vendor String,
    Model String,
    Ios_Version String,
    Description String,
    Wan String,
    Service_Provider String,
    Site String,
    Site_Cidr String,
    Poll Bool,
    Poll_Qos Bool,
    Poll_Flow Bool,
    Poll_Ip_Sla Bool,
    Poll_Routing Bool,
    Poll_Lan Bool,
    Poll_Interval_Msec UInt32,
    Username String,
    Password String,
    Golden_File String,
    Fetch_Time DateTime
) ENGINE = MergeTree()
ORDER BY (Host, Fetch_Time)
SETTINGS index_granularity = 8192;

EOSQL
