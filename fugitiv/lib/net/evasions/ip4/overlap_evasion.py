#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ..baseevasion     import SignatureEvasion
from ..testinfoevasion import TestInfoBasedEvasion
from .. import common
from .. import conf

import fragutils


class IP4OverlapFragEvasion(TestInfoBasedEvasion, SignatureEvasion):

    def __init__(self, testid, outputid, reverse, signature=None):
        # Init a signature Evasion on IP layer
        TestInfoBasedEvasion.__init__(self, conf.overlap_evasion, testid, outputid, reverse)
        SignatureEvasion.__init__(self, IP, signature)

    def evade_signature(self, pkt, sign_begin, sign_size):

        frag_id = random.randint(0, 65535)

        def fragment_maker(offset, payload, frag_info):
            fragment = IP(src=pkt[IP].src, dst=pkt[IP].dst,
                          proto=pkt[IP].proto, frag=offset,
                          flags="MF+DF", id=frag_id) / Raw(payload)

            if frag_info is None:
                if offset != 0:
                    # last fragment : no MF flag
                    fragment[IP].flags = "DF"
                else:
                    # first fragment
                    # nothing to do
                    pass

            return fragment

        fragment_list = common.fragmentmaker.make_fragment_evasion(
            payload=str(pkt[IP].payload),
            fragment_maker=fragment_maker,
            frag_infos_list=self._test_info['frags'][self._outputid],
            evaded_area=self._test_info['evaded'],
            signature_begin=sign_begin,
            signature_end=sign_begin + sign_size - 1,
            pre_frag_size=1,  # create fragment at egin and end for better clarity
            post_frag_size=1,
            offset_coef=8)

        if self._reverse:
            fragment_list = common.reverse_frag_list(fragment_list, True, True)

        fragutils.print_frag_list(fragment_list)

        return fragment_list

    @staticmethod
    def evasion_list(signature):
        input_list = TestInfoBasedEvasion.get_all_tests(conf.overlap_evasion)
        evasion_list = []
        for t in input_list:
            evasion_list.append(IP4OverlapFragEvasion(testid=t[0], outputid=t[1],
                    reverse=t[2], signature=signature))
        return evasion_list

