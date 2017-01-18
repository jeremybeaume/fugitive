#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import lib

for evasion in lib.net.evasions.IP4OverlapFragEvasion.evasion_list(None):
    lib.test.test_http_evasion(evasion)


for evasion in lib.net.evasions.IP4MFFlagEvasion.evasion_list(None):
    lib.test.test_http_evasion(evasion)