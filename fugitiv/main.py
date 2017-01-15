#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


from lib.utils import *
from scapy.all import *

from lib.net.tcpsocket import *

from lib.net.evasions import *

from lib.net.evasions.ip4.fragtest_def import *

def test_evasion(test_id, output, reverse):
    print
    signature = "abcdefghijklmnopqrstuvwxyz"

    frag_evasion = IP4OverlapFragEvasion("efgh", testid=test_id,
            outputid=output, reverse=reverse);


    s = TCPsocket("eth1", "10.0.10.2", 80, evasion=frag_evasion)
    s.connect()

    payload="GET /?data="+signature+" HTTP/1.1\r\nHost:10.0.10.2\r\n\r\n"
    s.write(payload)

    try:
        rep = s.read()
    except IOError:
        rep = ""

    if signature in rep :
        raise_success("SUCCESS")
    else:
        raise_error("FAIL")
       

    s.close()

for test_id in overlap_evasion.keys():
        test_info = overlap_evasion[test_id]
        for r in range(0, len(test_info['output'])):
            test_evasion(test_id, r, False)
            if test_info['reverse']:
                test_evasion(test_id, r, True)

