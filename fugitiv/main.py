#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


from lib.utils import *
from lib.net.ifacelistener import *
from scapy.all import *


for i in range(0,3):
    pkt = wait_for_packet(iface="eth1", condition=(lambda pkt : pkt[IP].src == "10.0.10.2"))
    pkt.show()