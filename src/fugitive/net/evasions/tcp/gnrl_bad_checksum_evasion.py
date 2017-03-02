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


class TCPBadChecksumEvasion(BaseEvasion):
    """
    Mess with defragmenting key :
    inject a fragment with same IPsrc, sameID, but and broadcast IP dst
    """

    evasion_folder = "TCP/General"
    evasion_list = []

    def __init__(self, evasion_type, spoofed_dst=None):
        name = "Bad Checksum " + evasion_type
        evasion_id = "BadChksum." + evasion_type

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

        pkt = pkt.__class__(str(pkt))
        pkt[TCP].chksum += 255  #bad checksum

        packet_list = [pkt]

        if self._evasion_type == 'inject':
            packet_list += [pkt_saved]

        return packet_list

    def get_description(self):
        return ("Change checksum to bad value")

TCPBadChecksumEvasion.evasion_list = [TCPBadChecksumEvasion('inject'),
                                       TCPBadChecksumEvasion('bypass')]
