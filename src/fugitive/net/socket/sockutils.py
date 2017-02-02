#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


import socket
import random
import netifaces
import scapy.all


def gethostbyname(name):
    """ Lookup hostname """
    return socket.gethostbyname(name)

_used_ports = []


def get_source_port():
    """ Return an available source port number """
    global _used_ports
    while 1:
        p = random.randint(1000, 10000)
        if p not in _used_ports:
            _used_ports.append(p)
            return p


def get_iface_mac(name):
    """ Return mac addr for an interface """
    return netifaces.ifaddresses(name)[netifaces.AF_LINK][0]["addr"]


def get_iface_ip4(name):
    """ Return IPv4 addr for an interface """
    return netifaces.ifaddresses(name)[netifaces.AF_INET][0]["addr"]

def get_iface_ip4_broadcast(name):
    return netifaces.ifaddresses(name)[netifaces.AF_INET][0]["broadcast"]

def get_iface_to_target(target):
    return scapy.all.conf.route.route(target)[0]


def parse_target_port(string):
    s = string.split(':')
    if len(s) != 2:
        raise ValueError("Target format is TARGET:PORT")
    try:
        port = int(s[1])
    except ValueError:
        raise ValueError("Incorrect port number \"{}\"".format(str(s[1])))

    return (gethostbyname(s[0]), port)
