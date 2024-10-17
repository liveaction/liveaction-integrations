# LiveWire App for Splunk
---

## Purpose

### LiveWire

The LiveWire App for Splunk has several premade dashboards which utilize telemetry sent from a LiveWire Packet Capture device. The dashboards may serve useful in many situations, including Network Performance Monitoring and Security Operations.

Many of the provided graphics may provide the ability to click-through to the LiveWire web application to either perform more detailed analysis or download relevant packets.

### LiveNX

As of 24.2.0, this app now ships with dashboards to ingest telemetry from LiveNX. There are three panels: alerts, network findings, and security findings. LiveNX uses Open Telemetry to send these findings to your Splunk endpoint.

## Prerequisites

You may find the following guide helpful to get ipfix/netflow traffic ingested into your splunk ecosystem: [Splunk Official Guide](https://www.splunk.com/en_us/blog/tips-and-tricks/splunking-netflow-with-splunk-stream-part-1-getting-netflow-data-into-splunk.html)

The following official splunk apps are also required to ingest netflow/ipfix:
1. **Splunk App for Stream on Search Heads** - [splunkbase link](http://splunkbase.splunk.com/app/1809)
2. **Splunk Add-On for Stream Wire Data** - [splunkbase link](http://splunkbase.splunk.com/app/5234)

On the host that contains the forwarder, ensure that *streamfwd.conf* exists at `$STREAMFWD_HOME/local/streamfwd.conf`.
A default configuration may look like:
        [streamfwd]
        port = 8889
        processingThreads = 4
        httpEventCollectorToken = \<your token\>
        indexer.0.uri = <indexer ip>:8088
        netflowReceiver.0.ip = <receiver ip>
        netflowReceiver.0.port = 9995
        netflowReceiver.0.decoder = netflow
        netflowReceiver.0.decodingThreads = 8

NOTE: Be sure that ports are not blocked by a firewall and are approved by your security team.

## Architecture

The **splunk_app_stream_ipfix_livewire** add-on must be installed on the forwarder.

## Installation

Install this app through Splunk Web. Click: Apps -> Manage Apps -> Install app from file. Select the .tgz from your filesystem. If prompted for a Restart, select Restart now.

Verify the installation worked in Splunk Web by navigating to Apps -> LiveWire App.

## Uninstall

On the host running splunk: delete the following directory `$SPLUNK_HOME/etc/apps/livewire_app`

Restart your splunk instance.

## Author

LiveAction

## Support

Developer-Supported
<splunk-support@liveaction.com>

### Copyright (c) 2024 LiveAction , Inc. All rights reserved.