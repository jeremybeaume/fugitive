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

import random
import sys
from scapy.all import *

from ....utils import *


def print_ip_frag_list(fraglist, logger, display_more={}):
    """
    Display ip fragments list
    display_more is a dict{attribute:max_char_size}
    to display protol for example, use {'proto':4}
    it will display a 4 char wide field with protocol value
    flags and id are always displayed
    """
    verbose = 1
    i = 0
    for frag in fraglist:
        i += 1
        flag_str = get_flags_str(frag.flags, "MDE", spaces=True)

        logger.write(
            'Frag {:>2} (id={:<5},flag={:<3}'.format(i, frag[IP].id, flag_str), verbose=verbose)
        for k, v in display_more.iteritems():
            # ",key={<size}".format(value)
            logger.write(
                ("," + k + "={:<" + str(v) + "}").format(getattr(frag[IP], k)), verbose=verbose)
        logger.write(") : ", verbose=verbose)
        logger.write(' ' * frag[IP].frag * 8, verbose=verbose)
        logger.write(get_non_ascii_string(
            str(frag[IP].payload)), verbose=verbose)
        logger.println(verbose=verbose)


def print_tcp_frag_list(fraglist, logger, display_more={}):
    """
    Display tcp fragments list
    display_more is a dict{attribute:max_char_size}
    to display protol for example, use {'proto':4}
    it will display a 4 char wide field with protocol value
    flags are always displayed
    """
    verbose = 1
    i = 0
    min_seq = min(p[TCP].seq for p in fraglist)
    for frag in fraglist:
        i += 1
        flag_str = get_flags_str(frag[TCP].flags, "FSRPAUEC", spaces=True)

        logger.write(
            'Frag {:>2} (flag={:<8}'.format(i, flag_str), verbose=verbose)
        for k, v in display_more.iteritems():
            # ",key={<size}".format(value)
            logger.write(
                ("," + k + "={:<" + str(v) + "}").format(getattr(frag[TCP], k)), verbose=verbose)
        logger.write(") : ", verbose=verbose)
        logger.write(' ' * (frag[TCP].seq - min_seq), verbose=verbose)
        logger.write(get_non_ascii_string(
            str(frag[TCP].payload)), verbose=verbose)
        logger.println(verbose=verbose)
