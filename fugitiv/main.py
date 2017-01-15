#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


from lib.utils import *
from scapy.all import *

from lib.net.tcpsocket import *

from lib.net.evasions import *


def test_evasion(test_id, output, reverse):
    signature = "abcdefghijklmnopqrstuvwxyz"

    frag_evasion = IP4OverlapFragEvasion(signature, testid=test_id,
            outputid=output, reverse=reverse);


    s = TCPsocket("eth1", "10.0.10.2", 80, evasion=frag_evasion)
    s.connect()

    payload="GET /?data="+signature+" HTTP/1.1\r\nHost:10.0.10.2\r\n\r\n"
    s.write(payload)

    print
    print
    print s.read()

    s.close()

test_evasion(1, 0, False)
test_evasion(1, 0, True)