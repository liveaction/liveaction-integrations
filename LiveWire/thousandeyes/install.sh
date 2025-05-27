#!/bin/bash

cd /home/admin/liveaction_thousandeyes

source ./.env

curl -Os https://downloads.thousandeyes.com/agent/install_thousandeyes.sh
chmod +x install_thousandeyes.sh
./install_thousandeyes.sh -l /var/log -b "${THOUSANDEYES_TOKEN}"