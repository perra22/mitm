###### To compile ######

g++ -o mms_nfq mms_nfq.cpp -lnetfilter_queue

###### To activate NFQUEUE ######

iptables -t mangle -A POSTROUTING -p tcp --sport 102 -j NFQUEUE

###### To activate forwarding ######

sysctl -w net.ipv4.ip_forward=1
