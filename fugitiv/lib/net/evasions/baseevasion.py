#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

from scapy.áll import *

class BaseAbstractEvasion:
    """ Base Class for all evasion technics """

    def __init__(self):
        pass

    def evade(self, pkt):
        """
        Apply the evasion technic
        Takes a packet, and returns a packet list
        """
        raise NotImplemetedError


class SignatureEvasion(BaseAbstractEvasion):
    """
    Evasion that avoid matching a signature based algorithm
    """

    def __init__(self, signature):
        BaseAbstractEvasion.__init__(self)
        self._signature = signature

    def evade(self, pkt):
        self.evade_signature(self, signature)

    def evase_signature(self, pkt, signature):
        """ Evade the signature """
        raise NotImplemetedError
