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


class TCPFinInWindowEvasion(BaseEvasion):
    """
    Inject a FIN in the window, but not the next SEQ (RFC 5961)
    """

    evasion_folder = "TCP/Window"
    evasion_list = []

    def __init__(self):
        name = "Fin in Window"
        evasion_id = "FinInWin"

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type='bypass', layer=TCP)

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):
        fin = socket.make_pkt(flags="FA")
        fin[TCP].seq += 10  # in window, but not next SEQ
        return [fin, pkt]

    def get_description(self):
        return """Inject a Fin inside the window (but not next SEQ : RFC 5961)"""

TCPFinInWindowEvasion.evasion_list = [TCPFinInWindowEvasion()]
