#!/bin/bash
#
# start.sh
# 
# This script is called by the PSA API when the PSA is requested to be started.


#mitmdump -p 8081 -T &

ebtables -t nat --flush
ebtables -t broute --flush
iptables -t nat --flush

ebtables -t nat -A PREROUTING --logical-in br0 -p ipv4 --ip-protocol 6 --ip-destination-port 80 -j redirect --redirect-target ACCEPT
ebtables -t nat -A PREROUTING --logical-in br0 -p ipv4 --ip-protocol 6 --ip-destination-port 443 -j redirect --redirect-target ACCEPT

ebtables -t nat -A PREROUTING --logical-in br0 -p arp --arp-ip-dst 10.2.4.1 -j redirect --redirect-target ACCEPT


iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i br0 -p tcp --dport 443 -j REDIRECT --to-port 8081

mitmdump $(< psaConfigs/psaconf) &

echo "PSA Started"



exit 1;