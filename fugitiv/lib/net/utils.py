#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


import socket
import random
import netifaces

def gethostbyname(name):
    return socket.gethostbyname(name)

def get_source_port():
    return random.randint(1000,6000)

def get_iface_ip4(name):
    return netifaces.ifaddresses(name)[netifaces.AF_INET][0]["addr"]
