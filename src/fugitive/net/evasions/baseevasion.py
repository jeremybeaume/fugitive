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


class BaseEvasion:
    """
    Evasion that avoid matching a signature based algorithm
    """

    def __init__(self, name, evasionid, evasion_type, layer):
        """
        Will search for a signature in the <layer> payload
        If a packet comes being Ether / IP / TCP / Raw
        layer = IP means the signature is searched in packet[IP].payload = TCP / Raw
        """
        self._layer = layer
        self._name = name
        self._evasionid = evasionid
        self._evasion_type = evasion_type

    def evade(self, socket, pkt, logger):
        """
        Evade any packet
        called by the socket when a packet does not match the signature
        default is to do nothing
        """
        pass

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):
        """
        Evade the signature, starting in self._layer payload at begin and finishing at end
        pkt is a full layer 2 pkt to evade
        This method is called when the signature is matched by the socket
        The default behavior is to call evade
        An evasion that does not care about the signature should only overwrite evade
        """
        return self.evade(socket, pkt, logger)

    def get_name(self):
        return self._name

    def get_id(self):
        return self._evasionid

    def get_description(self):
        return "Please overwrite get_description(self)"

    def get_type(self):
        return self._evasion_type

    def get_layer(self):
        return self._layer
