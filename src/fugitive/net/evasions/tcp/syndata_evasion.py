#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


from scapy.all import *

from ..baseevasion import BaseEvasion
from .. import common

from ...socket.defines import TCPstates


class TCPSynDataEvasion(BaseEvasion):
    """
    Inject payload in the SYN packet
    """

    evasion_folder = "TCP/Connection"
    evasion_list = []

    def __init__(self):
        name = "SYN data connection bypass"
        evasion_id = "SynData"

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type='bypass', layer=TCP)

    def evade(self, socket, pkt, logger):
        if pkt[TCP].flags == TCPstates.SYN:
            del pkt[TCP].chksum
            del pkt[IP].chksum
            del pkt[IP].len
            pkt = pkt / Raw(socket.data)
            socket.data = ''

        return [pkt]

    def get_description(self):
        return """Inject data in the first SYN packet"""

TCPSynDataEvasion.evasion_list = [TCPSynDataEvasion()]
