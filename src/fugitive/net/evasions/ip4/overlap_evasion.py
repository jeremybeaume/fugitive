#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ..testinfoevasion import TestInfoBasedEvasion
from .. import common
from .. import testdef


class IP4OverlapFragEvasion(TestInfoBasedEvasion):
    """
    Evade at IPv4 level following testdef.overlap_evasion
    Includes a pre evasion fragment and post evasion fragment,
    to not risk to mess with mf flag, and get false positive (wrong reason for evasion)
    """

    evasion_folder = "IPv4/Fragmentation/Overlap"
    evasion_list = []

    def __init__(self, testid, outputid, reverse, evasion_type):
        # Init a signature Evasion on IP layer
        TestInfoBasedEvasion.__init__(
            self, IP, testdef.overlap_evasion, testid, outputid, reverse, evasion_type)

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

        common.fragutils.print_ip_frag_list(fragment_list, logger)

        return fragment_list

TestInfoBasedEvasion.generate_evasion_list(
    testdef.overlap_evasion, IP4OverlapFragEvasion)
