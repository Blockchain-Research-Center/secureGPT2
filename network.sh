#!/bin/bash

# Network interface name
INTERFACE="lo"

# Bandwidth limit (e.g., 1mbit, 500kbit)
BANDWIDTH="100mbit"

# Delay
DELAY="40ms"

# Setup the root qdisc with HTB (Hierarchical Token Bucket)
sudo tc qdisc add dev $INTERFACE root handle 1: htb default 10

# Add class for the bandwidth limit
sudo tc class add dev $INTERFACE parent 1: classid 1:1 htb rate $BANDWIDTH

# Add qdisc for delay using netem
sudo tc qdisc add dev $INTERFACE parent 1:1 handle 10: netem delay $DELAY

# Add filter to direct all traffic to the above class
sudo tc filter add dev $INTERFACE protocol ip parent 1:0 prio 1 u32 match ip src 0.0.0.0/0 flowid 1:1

echo "Bandwidth limit set to $BANDWIDTH with $DELAY delay on $INTERFACE."
