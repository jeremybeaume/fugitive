#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import random
from scapy.all import *

from ..baseevasion import BaseEvasion
from .. import common


class IP4FragProtoEvasion(BaseEvasion):
    """
    Mess with defragmenting key :
    to put together the fragment, is the key simply (IPsrc, fragID),
    or does it include protocol ?
    """

    evasion_folder = "IPv4/Fragmentation/Identifier"
    evasion_list = []

    def __init__(self, evasion_type):
        name = "Fragment Protocol " + evasion_type
        evasion_id = "FragProt." + evasion_type

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type=evasion_type, layer=IP)

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):

        # when injecting : inject a tcp reset
        if self._evasion_type == 'inject':
            pkt_saved = pkt
            pkt = socket.make_pkt(flags="RA")

        frag_id = random.randint(0, 65535)

        # use scapy internal fragment method
        fragment_list = fragment(pkt, fragsize=len(pkt[IP].payload) / 3)
        for i in range(0, len(fragment_list)):
            p = fragment_list[i]
            p[IP].id = frag_id
            del p[IP].chksum
            fragment_list[i] = p

        fragment_list[1][IP].proto += 5  # mess with protocol

        common.fragutils.print_ip_frag_list(
            fragment_list, logger, display_more={'proto': 3})

        if self._evasion_type == 'inject':
            fragment_list += [pkt_saved]

        return fragment_list

    def get_description(self):
        return ("Change the proto field between the fragment :\n"
                "Check packet indentification against RFC 791")


IP4FragProtoEvasion.evasion_list = [IP4FragProtoEvasion('inject'),
                                    IP4FragProtoEvasion('bypass')]
