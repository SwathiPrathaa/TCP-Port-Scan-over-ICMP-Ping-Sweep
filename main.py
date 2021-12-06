###Performing a tcp port scan over hosts that are responding to ping request
from ipaddress import IPv4Network
from typing import List
from scapy.all import ICMP, IP, sr1, TCP
import random
from scapy.all import *


print("----------------------------------------------------------------------------------------------------------------------------")
print("----------------------------------------------------------------------------------------------------------------------------")
print("-----------------------------------------------------------TCP PORT SCAN AFTER ICMP PING-------------------------------------")
print("----------------------------------------------------------------------------------------------------------------------------")
print("----------------------------------------------------------------------------------------------------------------------------")


##performing tcp-port scan to find open ports for responding hosts in the network
def tcp_scan(host: str, ports: List[int]):
    count1 = 0

    for dstp in ports:
        srcp = random.randint(1025, 65534)
        response = sr1(
            IP(dst=host)/TCP(sport=srcp, dport=dstp, flags="S"), timeout=1,
            verbose=0,
        )
        if response is None:
            print(f"{host}:{dstp} did not send any response !!.")

        elif(response.haslayer(TCP)):
            if(response.getlayer(TCP).flags == 0x12):
                send_rst = sr1(
  IP(dst=host)/TCP(sport=srcp, dport=dstp, flags='R'),
                    timeout=1,
                    verbose=0,
                )
                count1 = count1+1
                print(f"{host}:{dstp} accepted the SYN request and is open.")

            elif (response.getlayer(TCP).flags == 0x14):
                print(f"{host}:{dstp} is closed!!!.")

    print(f"No.of ports open for host :{host} is :", count1,"!!!!")



##defining a subnet of hosts 
net = "52.84.6.0/30"

tcp_port_list = [22, 23, 80, 443]


#try:
#       addr=IPv4Network(net)
#except:
#       addr.AddressValueError(ValueError)
#       addr.NetmaskValueError(ValueError)


addr=IPv4Network(net)
count = 0
##performing icmp ping to check for ip's that respond to the request

for host in addr:
    if (host in (addr.network_address, addr.broadcast_address)):
        # Skip network and broadcast addresses
        continue

    response = sr1(IP(dst=str(host))/ICMP(), timeout=2, verbose=0)

    if response is None:
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print(f"{host} is down or not responding!!!!.")
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    elif (
        # type3-destination unreachable
        int(response.getlayer(ICMP).type) == 3 and
        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
    ):
        print(f"{host} is blocking ICMP.")
    else:

        print(f"{host} is responding to ICMP !!.")
        print("-----------------------------------")
        print(f"TCP port scan for {host} !!")
        print("-----------------------------------")
   tcp_scan(str(host), tcp_port_list)
        print("-----------------------------------")
        count += 1

print(f"{count}/{addr.num_addresses} hosts are online and available!!.")
print("\n")
print("***********")
print("*DONE BY:                   *")
print("*19PD09 - DHIKSHITHA A      *")
print("*19PD38 - SWATHI PRATHAA P  *")
print("***********")
print("\n")
