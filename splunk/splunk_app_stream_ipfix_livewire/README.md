# Splunk App Stream IPFIX LiveWire
---

## Purpose

To translate non-standard IPFIX fields from a LiveWire to produce more useful, searchable network data.

## Prerequisites

You may find the following guide helpful to get ipfix/netflow traffic ingested into your splunk ecosystem: [Splunk Official Guide](https://www.splunk.com/en_us/blog/tips-and-tricks/splunking-netflow-with-splunk-stream-part-1-getting-netflow-data-into-splunk.html)

The following official splunk apps are also required to ingest netflow/ipfix:
1. **Splunk App for Stream on Search Heads** - [splunkbase link](http://splunkbase.splunk.com/app/1809)
2. **Splunk Add-On for Stream Wire Data** - [splunkbase link](http://splunkbase.splunk.com/app/5234)

You will also need a LiveWire to send telemetry, please contact <sales@liveaction.com> for information on purchasing a LiveWire product.

#### Sending Telemetry from LiveWire

In the Captures tab, create a new Liveflow Capture.

Use the following settings as a baseline in your Liveflow Capture:
- Capture to disk - enabled
- Capture Statistics
- - Timeline statistics - enabled
- - Application statistics - enabled
- Packet File Indexing
- - Application - enabled
- Records
- - LiveNX Telemtry - enabled
- - - Server - the ip of your forwarder with the port of your netflow receiver. This information is configured in `$STREAMFWD_HOME/local/streamfwd.conf`.
- - - All relevant options enabled

Start your capture!

## Install

Install this app through Splunk Web. Click: Apps -> Manage Apps -> Install app from file. Select the .tgz from your filesystem. If prompted for a Restart, select Restart now.

You may verify that the extension successfully installed in Splunk Web. Navigate to Apps -> Splunk Stream -> Configuration -> Configure Streams. Ensure the stream `livewire_livewire_netflow` has been created and is enabled. If it is disabled, please enable it. By default, this stream uses the `main` index. If you would like to change the index, you may configure that by editing the stream.

Optionally, disable the `netflow` metadata stream if it is not in use.

## Uninstall

On the host running splunk: delete the following directory: `$SPLUNK_HOME/etc/apps/splunk_app_stream_ipfix_livewire`

On the Splunk Web App, in the Splunk Stream app, navigate to Configuration. Click Configure Streams. Delete the *livewire_livewire_netflow* stream.

Restart your Splunk instance. `$SPLUNK_HOME/bin/splunk restart`

## Author

LiveAction

## Support

Developer-Supported
<splunk-support@liveaction.com>

#### Copyright (c) 2024 LiveAction , Inc. All rights reserved.