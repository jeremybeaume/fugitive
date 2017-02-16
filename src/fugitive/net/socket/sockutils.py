#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Fugitive : Network evasion tester
# Copyright (C) 2017 Jérémy BEAUME (jeremy [dot] beaume (a) protonmail [dot] com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


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
