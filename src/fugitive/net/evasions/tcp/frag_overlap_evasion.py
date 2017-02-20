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


class TCPOverlapFragEvasion(TestInfoBasedEvasion):
    """
    Evade at TCP level following testdef.overlap_evasion
    Includes a pre evasion fragment and post evasion fragment,
    next seq packet is sent at the end, to mess with memory inside
    the target TCP stack 9and not ack the data one after the other ...
    """

    evasion_folder = "TCP/Fragmentation/Overlap"
    evasion_list = []

    def __init__(self, testid, outputid, reverse, evasion_type='inject'):
        """ Init a signature Evasion on TCP layer
        evasion_type must be 'inject' (let to default value)
        itś actually not used, but there to be complaint with testinfo constructor ...
        """
        TestInfoBasedEvasion.__init__(
            self, IP, testdef.overlap_evasion, testid, outputid, reverse, 'bypass')

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):

        def fragment_maker(offset, payload, frag_info):
            fragment = (IP(src=pkt[IP].src, dst=pkt[IP].dst,
                           proto=pkt[IP].proto)
                        / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                              ack=pkt[TCP].ack, seq=pkt[TCP].seq + offset,
                              flags=pkt[TCP].flags)
                        / Raw(payload))
            return fragment

        fragment_list = common.fragmentmaker.make_fragment_evasion(
            payload=str(pkt[TCP].payload),
            fragment_maker=fragment_maker,
            frag_infos_list=self._test_info['frags'][self._outputid],
            evaded_area=self._test_info['evaded'],
            signature_begin=sign_begin,
            signature_end=sign_begin + sign_size - 1,
            pre_frag_size=5,  # create 5 bytes fragment at begin and end for better clarity
            post_frag_size=5,
            offset_coef=1)

        if self._reverse:
            fragment_list = common.reverse_frag_list(fragment_list, True, True)

        # ALWAYS send the pre_Fragment last, so it is not acked first (pointless)
        # This evasion plays in the tcp memory without any ACK !!
        fragment_list = fragment_list[1:] + [fragment_list[0]]

        common.fragutils.print_tcp_frag_list(fragment_list, logger)

        return fragment_list


TestInfoBasedEvasion.generate_evasion_list(
    testdef.overlap_evasion, TCPOverlapFragEvasion, select_type=['bypass'])
