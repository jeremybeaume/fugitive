#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Fugitive : Network evasion tester
# Copyright (C) 2017 Jérémy BEAUME (jeremy [dot] beaume (a) protonmail [dot] com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):

        # when injecting : inject a tcp reset
        if self._evasion_type == 'inject':
            pkt_saved = pkt
            pkt = socket.make_pkt(flags="RA")

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

        if self._evasion_type == 'inject':
            fragment_list += [pkt_saved]

        return fragment_list

TestInfoBasedEvasion.generate_evasion_list(
    testdef.overlap_evasion, IP4OverlapFragEvasion)
