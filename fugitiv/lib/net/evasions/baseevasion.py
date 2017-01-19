#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

from scapy.all import *


class BaseEvasion:
    """
    Evasion that avoid matching a signature based algorithm
    """

    def __init__(self, layer, signature=None):
        """ Will search for a signature in the layer payload """
        self.signature = signature
        self._layer = layer

    def _find_signature(self, pkt):
        if signature is None:
            return (-1, -1)
        """
        Search the signature in the layer payload content
        return (pos, len) of the matched content, (-1,-1) if not found
        """
        # Check layer and get layer payload
        if self._layer is not None:
            if pkt.haslayer(self._layer):
                data = str(pkt[self._layer].payload)
            else:
                return (-1, -1)  # the pakcet has not the interrested layer
        else:
            data = str(pkt)

        # search the signature
        p = data.find(self._signature)
        if p < 0:
            return (-1, -1)
        else:
            return (p, len(self._signature))

    def evade(self, pkt):
        """
        search for the signature, and launches evade_signature if found
        """
        (pos, size) = self._find_signature(pkt)
        if pos > -1 or self.signature is None:
            return self.evade_signature(pkt, pos, size)
        else:
            return [pkt]  # no evasion needed

    def evade_signature(self, pkt, sign_begin, sign_size):
        """ Evade the signature, starting in layer payload at begin and finishing at end """
        raise NotImplemetedError
