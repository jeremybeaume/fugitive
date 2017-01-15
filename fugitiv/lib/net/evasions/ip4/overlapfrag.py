#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME
"""
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
        
        # finding the first fragment offset containing the signature :
        sign_first_offset = int(sign_begin/8)
        # finding the last one :
        sign_last_offset = int((sign_begin+sign_size-1)/8)
        # -1 : we want the last char actual position

        number_offset = int(len(payload)-1/8) #last possible offset

        # we want the test to evade at least an offset between frst and last
        # First check if it is possible :
        evaded_offset = self._testinfo['evaded']['offset']
        evaded_size   = self._testinfo['evaded']['size']
        # calculate evasion size : the max(offset + size) of all test fragments
        evasion_size = max([
                frag['offset'] + len(frag['content'])
                for frag in self._testinfo[frags][0]
            ])
"""

