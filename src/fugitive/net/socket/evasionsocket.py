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

from ... import utils
from basetcpsocket import BaseTCP4Socket


class EvasionTCP4Socket(BaseTCP4Socket):
    """
    Socket able to evade some signature using evasions
    """

    def __init__(self, target_config, port, iface=None,
                 logger=utils.testlogger.none_logger,
                 ip_dst=None, ip_src=None, port_src=None,
                 evasion=None, signature=None):

        BaseTCP4Socket.__init__(self, target_config=target_config,
                                port=port, iface=iface, logger=logger)

        self._evasion = evasion
        self._signature = signature

        self.data = ''

    def connect(self, data=''):
        """
        Connect the socket as usual
        except self.data will hold the data to be writen
        some TCP evasion may read those data to insert payload
        in the very firsts packets
        """
        self.data = data
        BaseTCP4Socket.connect(self)
        if len(self.data) > 0:
            self.write(self.data)
            self.data = ''

    def _send_pkt(self, pkt):
        """ Sends a packet, and apply evasion if not None """
        # evade packet
        if self._evasion is not None:
            (sign_begin, sign_size) = self._find_signature(pkt)
            # returns (-1,-1) if self._signature is none
            if sign_size > 0:  # if signature matched
                pkt_list = self._evasion.evade_signature(socket=self, pkt=pkt, sign_begin=sign_begin,
                                                         sign_size=sign_size, logger=self._logger)
            else:
                pkt_list = self._evasion.evade(
                    socket=self, pkt=pkt, logger=self._logger)
        else:
            pkt_list = [pkt]

        # send evaded packets
        for packet in pkt_list:
            BaseTCP4Socket._send_pkt(self, packet)

    def _find_signature(self, pkt):
        """
        Search the signature in the layer payload content
        return (begin, size) of the matched content, (-1,-1) if not found
        """

        if self._signature is None:
            return (-1, -1)

        # Check layer and get layer payload
        layer = self._evasion.get_layer()
        if layer is not None:
            if pkt.haslayer(layer):
                data = str(pkt[layer].payload)
            else:
                return (-1, -1)  # the pakcet has not the interrested layer
        else:
            data = str(pkt)

        # search the signature
        p = data.find(str(self._signature))
        if p < 0:
            return (-1, -1)
        else:
            return (p, p + len(self._signature))
