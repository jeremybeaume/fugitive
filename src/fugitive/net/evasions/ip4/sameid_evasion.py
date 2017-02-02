#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import random
from scapy.all import *

from ..baseevasion import BaseEvasion
from .. import common


class IP4SameIdEvasion(BaseEvasion):

    evasion_folder = "IPv4/Fragmentation/Identifier"
    evasion_list = []

    def __init__(self, evasion_type):
        name = "Same Frag ID " + evasion_type
        evasion_id = "SameId." + evasion_type

        BaseEvasion.__init__(
            self, name=name, evasionid=evasion_id,
            evasion_type=evasion_type, layer=IP)

    def evade_signature(self, socket, pkt, sign_begin, sign_size, logger):

        frag_id = random.randint(0, 65535)

        # use scapy internal fragment method
        # ensute the signature is not in the first fragment (which may not enter
        # in the defragmentation algorithm, depending on implementation)
        if sign_begin > 0:
            frag_size = len(pkt[IP].payload) / (sign_begin / 2)
        else:
            frag_size = len(pkt[IP].payload) / 3

        fragment_list = fragment(pkt, fragsize=frag_size)

        dumb_list = []
        for i in range(0, len(fragment_list)):
            p = fragment_list[i]
            p.id = frag_id
            del(p.chksum)

            dumb = p.copy()
            del dumb[IP].payload
            dumb[IP].payload = "-" * len(p[IP].payload)
            del dumb[IP].chksum

            dumb_list.append(dumb)

        fragment_list = dumb_list + fragment_list

        common.fragutils.print_ip_frag_list(fragment_list, logger)

        return fragment_list

    def get_description(self):
        return """Inject a blank packet fragmented with an ID, and then the
        paylaod fragmented with the same ID. Some implementation may consider
        the secand packet fragments to be late fragmented for the first packet
        and ignore them, while other might see it as a second packet."""


IP4SameIdEvasion.evasion_list = [IP4SameIdEvasion('inject'),
                                 IP4SameIdEvasion('bypass')]
