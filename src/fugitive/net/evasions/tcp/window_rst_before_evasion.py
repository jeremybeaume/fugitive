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


class TCPRstBeforeWindowEvasion(BaseEvasion):
    """
    Inject a RST before the window
    """

    evasion_folder = "TCP/Window"
    evasion_list = []

    def __init__(self):
        name = "Reset before Window"
        evasion_id = "RstBeforeWin"

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type='bypass', layer=TCP)

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):
        rst = socket.make_pkt(flags="RA")
        # (reasonable) supposely outside window, but not next SEQ
        rst[TCP].seq -= 10
        return [rst, pkt]

    def get_description(self):
        return """Inject a RST before the window"""

TCPRstBeforeWindowEvasion.evasion_list = [TCPRstBeforeWindowEvasion()]
