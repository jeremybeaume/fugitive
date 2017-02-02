#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

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

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):
        """
        Evade the signature, starting in self._layer payload at begin and finishing at end
        pkt is a full layer 2 pkt to evade
        if evasion_type is 'inject' : pkt is a TCP RST to inject
        """
        raise NotImplemetedError

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
