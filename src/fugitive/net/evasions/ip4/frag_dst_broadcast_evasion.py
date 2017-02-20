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

from ..baseevasion import BaseEvasion
from .. import common


class IP4FragDstBroadcastEvasion(BaseEvasion):
    """
    Mess with defragmenting key :
    inject a fragment with same IPsrc, sameID, but and broadcast IP dst
    """

    evasion_folder = "IPv4/Fragmentation/Identifier"
    evasion_list = []

    def __init__(self, evasion_type, spoofed_dst=None):
        name = "Fragment Broadcast Destination " + evasion_type
        evasion_id = "FragDestBroadcast." + evasion_type

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type=evasion_type, layer=IP)

        self._spoofed_dst = spoofed_dst

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):

        # when injecting : inject a tcp reset
        if self._evasion_type == 'inject':
            pkt_saved = pkt
            pkt = socket.make_pkt(flags="RA")

        frag_id = random.randint(0, 65535)

        # use scapy internal fragment method
        fragment_list = fragment(pkt, fragsize=len(pkt[IP].payload) / 3)
        for i in range(0, len(fragment_list)):
            p = fragment_list[i]
            p[IP].id = frag_id
            del p[IP].chksum
            fragment_list[i] = p

        dst = self._spoofed_dst
        if dst is None:
            # use src + 1 as dst
            s = fragment_list[1][IP].dst.split(".")
            s[3] = str(int(s[3]) + 1)
            dst = ".".join(s)

        fragment_list[1][IP].dst = socket.target_config[
            "ipv4_broadcast"]  # change packet destination

        common.fragutils.print_ip_frag_list(
            fragment_list, logger, display_more={'dst': 15})

        if self._evasion_type == 'inject':
            fragment_list += [pkt_saved]

        return fragment_list

    def get_description(self):
        return ("Inject fragment with broacast as destination IP")

IP4FragDstBroadcastEvasion.evasion_list = [IP4FragDstBroadcastEvasion('inject'),
                                           IP4FragDstBroadcastEvasion('bypass')]
