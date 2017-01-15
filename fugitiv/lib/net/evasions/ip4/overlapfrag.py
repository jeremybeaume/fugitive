#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

from scapy.all import *
from ..baseevasion import *

from fragtest_def import *

from ..divideutils import *

import fragutils

class IP4OverlapFragEvasion(SignatureEvasion):

    def __init__(self, signature, testid, outputid, reverse):
        ## Init a signature Evasion on IP layer
        SignatureEvasion.__init__(self, signature, IP)

        self._testid = testid
        self._outputid = outputid
        self._reverse = reverse

        self._testinfo = overlap_evasion[testid]

    def evade_signature(self, pkt, sign_begin, sign_size):
        payload = str(pkt[IP].payload)
        
        # finding the first fragment offset containing the signature :
        sign_first_offset = int(sign_begin/8)
        # finding the last one :
        sign_last_offset = int((sign_begin+sign_size-1)/8)
        # -1 : we want the last char actual position

        last_offset = int((len(payload)-1) /8) #last possible offset value in the packet
        number_offset = last_offset + 1 #0 is an offset value =)

        evaded_offset = self._testinfo['evaded']['offset']
        evaded_size   = self._testinfo['evaded']['size']
        # calculate evasion size : the max(offset + size) of all test fragments
        evasion_size = max([
                frag['offset'] + len(frag['content'])
                for frag in self._testinfo['frags'][self._outputid] #get fragments for desired output
            ])

        # division of the offset space between the fragment groups
        # to match signature with evasion capacity
        # take a post_size of 1 : will be the only fragment without MF
        # at the end, so that the evasion only concerns overlaping
        sizes = compute_frag_size(payload_size = number_offset,
            pre_size = 1, post_size = 1,
            evaded_offset = evaded_offset,
            evaded_size   = evaded_size,
            evasion_size  = evasion_size,
            sign_begin = sign_first_offset,
            sign_end   = sign_last_offset)

        frag_list = fragutils.fragment_packet(pkt, self._testinfo['frags'][self._outputid], sizes)

        if self._reverse :
            frag_list.reverse()

        fragutils.print_frag_list(frag_list)

        return frag_list



