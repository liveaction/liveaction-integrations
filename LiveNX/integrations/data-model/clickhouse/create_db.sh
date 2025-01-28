#!/bin/bash
# so this script needs to be run only on the server

set -e

BASEDIR=$(dirname $0)
cd $BASEDIR


# v1.0
sh create_tables_1.0.sh
