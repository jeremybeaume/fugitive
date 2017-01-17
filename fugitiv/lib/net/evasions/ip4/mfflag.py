#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ..baseevasion import *
from .. import common
from .. import conf

import fragutils


class IP4MFFlagEvasion(SignatureEvasion):

    def __init__(self, signature, testid, outputid, reverse):
        # Init a signature Evasion on IP layer
        SignatureEvasion.__init__(self, signature, IP)

        self._testid = testid
        self._outputid = outputid
        self._reverse = reverse

        self._testinfo = conf.mf_flag_evasion[testid]

    def evade_signature(self, pkt, sign_begin, sign_size):

        frag_id = random.randint(0, 65535)

        def fragment_maker(offset, payload, frag_info):
            if frag_info is None:
                flag_value = None
            else:
                flag_value = frag_info['flags']

            fragment = IP(src=pkt[IP].src, dst=pkt[IP].dst,
                          proto=pkt[IP].proto, frag=offset,
                          flags=flag_value, id=frag_id) / Raw(payload)

            return fragment

        fragment_list = common.fragmentmaker.make_fragment_evasion(
            payload=str(pkt[IP].payload),
            fragment_maker=fragment_maker,
            frag_infos_list=self._testinfo['frags'][self._outputid],
            evaded_area=self._testinfo['evaded'],
            signature_begin=sign_begin,
            signature_end=sign_begin + sign_size - 1,
            pre_frag_size=0,  # create fragment at egin and end for better clarity
            post_frag_size=0,
            offset_coef=8)

        if self._reverse:
            fragment_list = common.reverse_frag_list(fragment_list, True, True)

        fragutils.print_frag_list(fragment_list)

        return fragment_list
