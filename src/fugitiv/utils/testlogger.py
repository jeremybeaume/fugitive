#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import os
import sys
import common
# logger printing everything on stdout


class TestLogger:
    """
    Log test data to a folder
    """

    def __init__(self, folder, name, verbose=0):
        self.folder = folder
        self.name = name
        self.verbose = verbose
        self.txt_trace = None
        self.pcap_out = None

    def write_pkt(self, pkt):
        pass

    def println(self, msg="", verbose=-1):
        self.write(msg + "\n", verbose)

    def write(self, msg, verbose=-1):
        if self.verbose >= verbose:
            sys.stdout.write(msg)
            sys.stdout.flush()

    def log_warning(self, msg):
        if self.verbose > 0:
            common.print_warning(msg)

    def log_error(self, msg):
        if self.verbose > 0:
            common.print_error(msg)

none_logger = TestLogger(None, None, -1)
stdout_logger = TestLogger(None, None, 32768)
