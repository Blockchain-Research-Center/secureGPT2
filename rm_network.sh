#!/bin/bash

# Network interface name
INTERFACE="lo"

# Delete the root qdisc from the lo interface
sudo tc qdisc del dev $INTERFACE root

echo "Removed all tc policies from $INTERFACE."
