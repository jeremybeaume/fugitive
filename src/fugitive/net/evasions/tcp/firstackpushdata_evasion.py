#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


from scapy.all import *

from ..baseevasion import BaseEvasion
from .. import common

from ...socket.defines import TCPstates


class TCPFirstAckPushDataEvasion(BaseEvasion):
    """
    Inject payload in the SYN packet
    """

    evasion_folder = "TCP/Connection"
    evasion_list = []

    def __init__(self):
        name = "First ACK PUSH data connection bypass"
        evasion_id = "FirstAckPushData"

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type='bypass', layer=TCP)

    def evade(self, socket, pkt, logger):
        if pkt[TCP].flags == TCPstates.ACK and socket.state == TCPstates.SYN_SENT:
            # this is the first ack packet
            del pkt[TCP].chksum
            del pkt[IP].chksum
            del pkt[IP].len
            pkt[TCP].flags = "PA"
            pkt = pkt / Raw(socket.data)  # insert data
            socket.data = ''

        return [pkt]

    def get_description(self):
        return """Inject data in the first ACK packet, and adds PUSH flag"""

TCPFirstAckPushDataEvasion.evasion_list = [TCPFirstAckPushDataEvasion()]
