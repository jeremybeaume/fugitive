#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


from lib.utils import *
from scapy.all import *

from lib.net.tcpsocket import *


s = TCPsocket("eth1", "10.0.10.2", 80)
s.connect()

payload="GET / HTTP/1.1\r\nHost:10.0.10.2\r\n\r\n"
s.write(payload)

print s.read()

s.close()
