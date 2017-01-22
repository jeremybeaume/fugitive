#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ..testinfoevasion import TestInfoBasedEvasion
from .. import common
from .. import conf

import fragutils


class IP4OverlapFragEvasion(TestInfoBasedEvasion):

    evasion_folder = "IPv4/Fragmentation/Overlap"
    evasion_list = []

    def __init__(self, testid, outputid, reverse, signature=None):
        # Init a signature Evasion on IP layer
        TestInfoBasedEvasion.__init__(
            self, IP, conf.overlap_evasion, testid, outputid, reverse, signature=signature)

    def evade_signature(self, pkt, sign_begin, sign_size, logger):

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

        fragutils.print_frag_list(fragment_list, logger)

        return fragment_list

TestInfoBasedEvasion.generate_evasion_list(
    conf.overlap_evasion, IP4OverlapFragEvasion)
