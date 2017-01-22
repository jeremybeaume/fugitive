#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys
import fugitiv

fugitiv.main_test.run_tests(
    "IPv4/Fragmentation/Overlap/2.0.0", fugitiv.test.http_evasion_tester, "./output", 0)
