#!/bin/bash
sysctl -w net.ipv4.ip_forward=0
iptables -F
echo "[+] Rules restored..."
