#!/bin/bash
#
# start.sh
# 
# This script is called by the PSA API when the PSA is requested to be started.


sysctl -w net.ipv4.ip_forward=1 
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8081



# Load PSA's current configuration
mitmdump < psaConfigs/conf

echo "PSA Started"

exit 1;
