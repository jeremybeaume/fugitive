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


from scapy.all import *

from ..baseevasion import BaseEvasion
from .. import common

from ...socket.defines import TCPstates


class TCPPushSynEvasion(BaseEvasion):
    """
    Add the SYN flag to the normal PUSH ACK packet
    """

    evasion_folder = "TCP/Connection"
    evasion_list = []

    def __init__(self):
        name = "Push to Syn evasion"
        evasion_id = "PushToSyn"

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type='bypass', layer=TCP)

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):
        payload = str(pkt[TCP].payload)
        #create 2 packets, dividing the signature in 2
        divide=sign_begin + sign_size/2

        syn_pkt = common.copy_pkt(pkt, TCP) # makes a new packet for scapy to compute fields
        syn_pkt[TCP].flags="SPA"
        syn_pkt = syn_pkt / Raw(payload[:divide])

        psh_pkt = common.copy_pkt(pkt, TCP)
        psh_pkt[TCP].seq += divide
        psh_pkt = psh_pkt / Raw(payload[divide:])

        pkt_list = [syn_pkt, psh_pkt]

        common.fragutils.print_tcp_frag_list(pkt_list, logger)

        return pkt_list

    def get_description(self):
        return """First syn packet turned into SYN PUSH with data"""

TCPPushSynEvasion.evasion_list = [TCPPushSynEvasion()]
