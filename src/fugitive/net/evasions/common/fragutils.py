#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

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
    """
    verbose = 1
    i = 0
    for frag in fraglist:
        i += 1
        flag_str = get_flags_str(frag.flags, "MDE", spaces=True)

        logger.write(
            'Frag {:>2} (id={:<5},flag={:<3}'.format(i, frag.id, flag_str), verbose=verbose)
        for k, v in display_more.iteritems():
            # ",key={<size}".format(value)
            logger.write(
                ("," + k + "={:<" + str(v) + "}").format(getattr(frag[IP], k)))
        logger.write(") : ")
        logger.write(' ' * frag[IP].frag * 8, verbose=verbose)
        logger.write(get_non_ascii_string(
            str(frag[IP].payload)), verbose=verbose)
        logger.println(verbose=verbose)
