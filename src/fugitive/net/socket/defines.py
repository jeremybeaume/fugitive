#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


class TCPstates:

    INIT, SYN_SENT, SYN_RECVD, ESTABLISHED = range(4)
    _state_str = ["INIT", "SYN_SENT", "SYN_RECVD", "ESTABLISHED"]

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
