#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ..baseevasion import *
from .. import common
from .. import conf

import fragutils

class IP4OverlapFragEvasion(SignatureEvasion):

    def __init__(self, signature, testid, outputid, reverse):
        ## Init a signature Evasion on IP layer
        SignatureEvasion.__init__(self, signature, IP)

        self._testid = testid
        self._outputid = outputid
        self._reverse = reverse

        self._testinfo = conf.overlap_evasion[testid]

    def evade_signature(self, pkt, sign_begin, sign_size):
        
        frag_id = random.randint(0, 65535)

        def fragment_maker(offset, payload, frag_info):
            fragment = IP( src = pkt[IP].src, dst=pkt[IP].dst,
                proto=pkt[IP].proto, frag=offset,
                flags="MF+DF", id=frag_id) / Raw(payload)

            if frag_info is None:
                if offset != 0:
                    #last fragment : no MF flag
                    fragment[IP].flags="DF"
                else:
                    #first fragment
                    #nothing to do
                    pass

            return fragment

        fragment_list = common.fragmentmaker.make_fragment_evasion(
            payload = str(pkt[IP].payload),
            fragment_maker  = fragment_maker,
            frag_infos_list = self._testinfo['frags'][self._outputid],
            evaded_area     = self._testinfo['evaded'],
            signature_begin = sign_begin,
            signature_end   = sign_begin + sign_size - 1,
            pre_frag_size   = 1, #create fragment at egin and end for better clarity
            post_frag_size  = 1,
            offset_coef = 8)
        
        if self._reverse :
            fragment_list = common.reverse_frag_list(fragment_list, True, True)

        fragutils.print_frag_list(fragment_list)

        return fragment_list
