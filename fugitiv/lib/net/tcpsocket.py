#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
import scapy.all as scapy
import utils

class TCPsocket:

    INIT,SYN_SENT,SYN_RECVD,ESTABLISHED = range(4)
    _state_str=["INIT","SYN_SENT","SYN_RECVD","ESTABLISHED"]

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self, iface, target, port):
        self._iface = iface

        self._dst_ip   = target
        self._dst_port = port
        self._src_ip   = "0.0.0.0"
        self._src_port = 0

        self._seq = 0
        self._ack = 0

        self._state = TCPState.INIT

    def connect(self):
        """
        Connect this socket
        """
        self._src_ip   = utils.get_iface_ip4(self._iface)
        self._src_port = utils.get_source_port()

        self._seq = random.randint(0,65536)
        self._ack = 0

        syn_pkt = self._make_pkt()
        syn_pkt[TCP].flags=SYN
        self.send_pkt(syn_pkt)


    def send_pkt(self, pkt):
        scapy.sendp(ETHER() / pkt, iface=self._iface)

    #### UTILS ####

    def _make_pkt(self):
        """ Create packet with current seq / ack """
        return   IP(src=self._src_ip, dst=self._dst_ip) \
                /TCP(sport=self._src_port, dport=self._dst_port,
                      seq=self._seq, ack=self._ack)        

    def is_answer(self, pkt):
        """ Return True if packet is destined to this socket """

    def __str__(self):
        s = "TCPConn[{}/{}:{}=>{}:{},{},seq={},ack={}]".format(
            self._iface,
            self._src_ip, self._src_port,
            self._dst_ip, self._dst_port,
            _state_str[self._state],
            self._seq, self._ack,
            )

