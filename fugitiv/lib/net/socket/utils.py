#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


import socket
import random
import netifaces

def gethostbyname(name):
    """ Lookup hostname """
    return socket.gethostbyname(name)

_used_ports = []
def get_source_port():
    """ Return an available source port number """
    global _used_ports
    while 1:
        p = random.randint(1000,10000)
        if p not in _used_ports :
            _used_ports.append(p)
            return p

def get_iface_mac(name):
    """ Return mac addr for an interface """
    return netifaces.ifaddresses(name)[netifaces.AF_LINK][0]["addr"]

def get_iface_ip4(name):
    """ Return IPv4 addr for an interface """
    return netifaces.ifaddresses(name)[netifaces.AF_INET][0]["addr"]