from netfilterqueue import NetfilterQueue
from scapy.all import *
from builtins import bytes
import os, sys, argparse, binascii

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--source', help="IP of the host from which to accept packets", required=True)
parser.add_argument('-p', '--port', help="Set the port from which to filter traffic", required=True)
parser.add_argument('-t', '--topic', help="Set the topic to compromise", required=True)
args = parser.parse_args()


def callback(packet):
    pkt = IP(packet.get_payload())

    pktHex = str(pkt).encode('utf-8').hex()
    checkHex = args.topic.encode('utf-8').hex()

    subs = isSubstring(checkHex, pktHex)
    if pkt.src != args.source and  subs != -1:
        print ('DROPPED')
        packet.drop()
    else:
        print ('ACCEPTED')
        packet.accept()


# Returns true if s1 is substring of s2
def isSubstring(s1, s2):
    M = len(s1)
    N = len(s2)

    # A loop to slide pat[] one by one
    for i in range(N - M + 1):

        # For current index i,
        # check for pattern match
        for j in range(M):
            if (s2[i + j] != s1[j]):
                break

        if j + 1 == M :
            return i

    return -1

def main():

    try:

        iptables_cmd = 'iptables -t raw -A PREROUTING -p tcp --dport ' + args.port + ' -j NFQUEUE --queue-num 1'
        cmd = os.system(iptables_cmd)
        print("[+] Setting IpTables rules")
        if cmd != 0:
            print("[-] setting iptables failed, exiting!")
            quit()
        #create NetfilterQueue object
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, callback)

        print("[+] Waiting for data...")
        print("[+] Accepting only from",args.source, "port", args.port)

        nfqueue.run()

    except KeyboardInterrupt:

        print("[+] Restoring iptables")
        #restore iptables
        os.system("iptables -F -t raw")
        print('[+] Exiting')
        nfqueue.unbind()


main()
