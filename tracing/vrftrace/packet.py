#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#
from scapy.all import *

dns = Ether(src="de:ad:be:ef:02:02", dst="de:ad:be:ef:02:03",type=0x800)/IP(src="1.1.1.1", dst="1.1.1.2",)/UDP(sport=53, dport=60185)/DNS(rd=1,qd=DNSQR(qname="www.thepacketgeek.com"))

sendp(dns, iface="veth0", loop=0, inter=0.2)
