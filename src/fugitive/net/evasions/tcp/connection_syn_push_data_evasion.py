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


class TCPSynPushDataEvasion(BaseEvasion):
    """
    Inject payload in the SYN packet
    """

    evasion_folder = "TCP/Connection"
    evasion_list = []

    def __init__(self):
        name = "SYN push data connect bypass"
        evasion_id = "SynPushData"

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type='bypass', layer=TCP)

    def evade(self, socket, pkt, logger):
        if pkt[TCP].flags == TCPstates.SYN:
            # makes a new packet for scapy to compute fields
            pkt = common.copy_pkt(pkt)
            pkt[TCP].flags = "SP"
            pkt = pkt / Raw(socket.data)
            socket.data = ''

        return [pkt]

    def get_description(self):
        return """First syn packet turned into SYN PUSH with data"""

TCPSynPushDataEvasion.evasion_list = [TCPSynPushDataEvasion()]
