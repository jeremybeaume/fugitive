#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random,sys
from scapy.all import *

from ....utils import *

def print_frag_list(fraglist):
    i=0
    for frag in fraglist:
        i+=1
        
        flag_str = get_flags_str(frag.flags, "MDE", spaces=True)

        sys.stdout.write('Frag {} (id={:<5},flag={:<3}): '.format(i,frag.id,flag_str))
        sys.stdout.write(' '*frag[IP].frag*8)
        print_non_ascii_string(str(frag[IP].payload))
        print

