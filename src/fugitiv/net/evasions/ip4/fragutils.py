#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
import sys
from scapy.all import *

from ....utils import *


def print_frag_list(fraglist, logger):
    verbose = 1
    i = 0
    for frag in fraglist:
        i += 1
        flag_str = get_flags_str(frag.flags, "MDE", spaces=True)

        logger.write(
            'Frag {} (id={:<5},flag={:<3}): '.format(i, frag.id, flag_str), verbose=verbose)
        logger.write(' ' * frag[IP].frag * 8, verbose=verbose)
        logger.write(get_non_ascii_string(
            str(frag[IP].payload)), verbose=verbose)
        logger.println(verbose=verbose)
