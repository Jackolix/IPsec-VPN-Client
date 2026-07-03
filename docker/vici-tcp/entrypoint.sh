#!/bin/sh
# Run charon in the foreground with the TCP vici socket from strongswan.conf.
set -eu

exec /usr/lib/strongswan/charon
