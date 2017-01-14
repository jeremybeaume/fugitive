#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME


import lib.utils
from lib.net.ifacelistener import *

lib.net.ifacelistener._get_listener("eth1")
lib.utils.sleep(5)
