# Splunk App Stream IPFIX LiveWire

## Purpose

To translate non-standard IPFIX fields from a LiveWire to produce more useful, searchable network data.

## Prerequisites

You may find the following guide helpful to get ipfix/netflow traffic ingested into your splunk ecosystem: [Splunk Official Guide](https://www.splunk.com/en_us/blog/tips-and-tricks/splunking-netflow-with-splunk-stream-part-1-getting-netflow-data-into-splunk.html)

The following official splunk apps are also required to ingest netflow/ipfix:
1. **Splunk App for Stream on Search Heads** - [splunkbase link](http://splunkbase.splunk.com/app/1809)
2. **Splunk Add-On for Stream Wire Data** - [splunkbase link](http://splunkbase.splunk.com/app/5234)

You will also need a LiveWire to send telemetry, please visit [our website](https://bluecatnetworks.com/contact-us/) for information on purchasing a LiveWire product.

#### Sending Telemetry from LiveWire

In the Captures tab, create a new Liveflow Capture.
- To receive security alerts, enable the OpenTelemetry (LiveFlow Alerts) output.
- To receive network and application data via ipfix, enable the IPFIX Telemetry output.

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

BlueCat Networks

## Support

Developer-Supported
<la-support@bluecatnetworks.com>

### Copyright (c) 2026 BlueCat Networks, Inc. All rights reserved.