# LIVEACTION-SPLUNK
---
Repo Page for all of the Splunk apps

Each individual file should be packaged up and submitted for review on splunkbase.

## Submitting the Application on splunkbase

Just submit the .tgz file to the application page. Automated review takes less than a day and will give feedback on what isn't passing.

The livewire_app (dashboards) is published at: https://classic.splunkbase.splunk.com/app/7217
The splunk_app_stream_ipfix_livewire (ipfix translation) is published at: https://classic.splunkbase.splunk.com/app/7216/

Quick checklist:
- Be sure no local/ directory exists. Only the default/ directory should be included.
- In app.conf, be sure that the checksum is not included. This is auto-populated when downloading the app. You will fail the tests if you include this (like I did).
- Be sure to increase the version number for every release. Even releases with small changes must have a different version number.
- For more information, read through Splunk's official guide on submitting apps.

## Tar it up

Splunk imports apps with a *.tgz file extension. This is how it should be distributed on splunkbase.

Run `tar -cvzf splunk_app_stream_ipfix_livewire.tgz splunk_app_stream_ipfix_livewire/`

Run `tar -cvzf liveaction_app.tgz liveaction_app`

## /Src

Contains a script to generate the app mappings, see the readme for more information.

## README

Refer to the individual README's in each app.
