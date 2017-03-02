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
import os
import sys
from scapy.all import *

import common
# logger printing everything on stdout


class TestLogger:
    """
    Log test data to a folder (stdout and pcap)
    """

    def __init__(self, folder, name, verbose=0):
        self._folder = folder
        self._name = name
        self._verbose = verbose

        self._txt_trace_file = None
        self._pcap_out = None

        if folder is not None and name is not None:
            if not os.path.isdir(folder):
                os.makedirs(folder)
            self._txt_trace_file = open(folder + "/" + name + ".txt", "w")

        self.pkt_list = []

    def write_pkt(self, pkt):
        """
        Add a packet to the packet list, THIS DOES NOT WRITE A PCAP !
        see write_pcap
        """
        self.pkt_list.append(pkt)

    def write_pcap(self):
        """
        Write the pcap output file, with packets from pkt_list
        """
        if self._folder is not None and self._name is not None:
            self._pcap_out = wrpcap(
                self._folder + "/" + self._name + ".pcap", self.pkt_list)

    def println(self, msg="", verbose=-1):
        self.write(msg + "\n", verbose)

    def write(self, msg, verbose=-1):
        if self._verbose >= verbose:
            sys.stdout.write(msg)
            sys.stdout.flush()
        self._txt_trace(msg)

    def log_warning(self, msg):
        if self._verbose > 0:
            common.print_warning(msg)
        self._txt_trace("[!] WARNING : " + msg + "\n")

    def log_error(self, msg):
        if self._verbose > 0:
            common.print_error(msg)
        self._txt_trace("[!] ERROR : " + msg + "\n")

    def close(self):
        """
        Logger must be closed after use :
        closes the txt output file
        write the pkt_list to the pcap_output file
        """
        if self._txt_trace_file is not None:
            self._txt_trace_file.close()
        self.write_pcap()

    def _txt_trace(self, msg):
        if self._txt_trace_file is not None:
            self._txt_trace_file.write(msg)

none_logger = TestLogger(None, None, -1)
stdout_logger = TestLogger(None, None, 32768)
