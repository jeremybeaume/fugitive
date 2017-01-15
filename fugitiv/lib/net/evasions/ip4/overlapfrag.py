#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

from scapy.all import *
from ..baseevasion import *

from fragtest_def import *

class IP4OverlapFragEvasion(SignatureEvasion):

    def __init__(self, signature, testid, reverse):
        ## Init a signature Evasion on IP layer
        SignatureEvasion.__init__(self, signature, IP)

        self._testid = testid
        self._reverse = reverse

        self._testinfo = overlap_test[testid]

    def evade_signature(self, pkt, sign_begin, sign_size):
        payload = str(pkt[IP].payload)
        print "Fragmenting around : "+payload[sign_begin:sign_begin+sign_size]

        return [pkt]
