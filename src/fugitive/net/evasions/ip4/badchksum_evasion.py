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


class IP4BadChecksumEvasion(BaseEvasion):

    evasion_folder = "IPv4/Fragmentation/General"
    evasion_list = []

    def __init__(self):
        # Init a signature Evasion on IP layer
        BaseEvasion.__init__(
            self, name="BadChecksum  Fragment injection", evasionid="BadChecksum",
            evasion_type='inject', layer=IP)

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

        p = fragment_list[1]
        p = p.__class__(str(p))
        p.chksum += 255
        fragment_list[1] = p

        common.fragutils.print_ip_frag_list(
            fragment_list, logger, display_more={'chksum': 5})

        if self._evasion_type == 'inject':
            fragment_list += [pkt_saved]

        return fragment_list

    def get_description(self):
        return """Inject a fragment with bad checksum, checks that the IDS computes the IP checksum"""


IP4BadChecksumEvasion.evasion_list = [IP4BadChecksumEvasion()]
