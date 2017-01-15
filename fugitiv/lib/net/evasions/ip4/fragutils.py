#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random,sys
from scapy.all import *

from ....utils.common import *

def fragment_packet(orig_pkt, frag_infos_list, sizes):
    """
    frag_info : test fragment infos
    'offset', 'content'

    sizes = array of group sizes
    index[0]  : initial fragment size (MF+DF)
    index[-1] : last fragment size (DF)
    """
    payload = str(orig_pkt[IP].payload)
    frag_list = []

    frag_id = random.randint(0, 65535)
    ip_header = IP(src=orig_pkt[IP].src, dst=orig_pkt[IP].dst,
        id=frag_id, flags="DF+MF", frag=0, proto=orig_pkt[IP].proto)

    #add first fragment
    if sizes[0] >0 :
        generated_content = payload[:sizes[0]*8]
        fragment_pkt = ip_header.copy() / Raw(generated_content)        
        fragment_pkt.frag = 0
        frag_list.append(fragment_pkt)

    for frag in frag_infos_list:
        # offset : sum the sizes of all preceding columns
        # 0 if pre_size column
        offset = sum(sizes[0 : 1 + frag['offset']])
        # generate content :
        content_list = frag['content']
        generated_content = ""
        current_offset = offset
        for i in range(0,len(content_list)):
            col_size = sizes[1 + i + frag['offset']]
            if content_list[i] == 0:
                generated_content += "-"*(col_size*8)
            else:
                #take packet content
                generated_content += str(payload[current_offset*8:(current_offset + col_size)*8])

            current_offset += col_size

        fragment_pkt = ip_header.copy() / Raw(generated_content)        
        fragment_pkt.frag = offset
        frag_list.append(fragment_pkt)

    #add last fragment
    offset = sum(sizes[0:-1])
    generated_content = payload[offset*8:]
    fragment_pkt = ip_header.copy() / Raw(generated_content)        
    fragment_pkt.frag = offset
    fragment_pkt.flags = "DF"    
    frag_list.append(fragment_pkt)

    return frag_list


def print_frag_list(fraglist):
    i=0
    for frag in fraglist:
        i+=1
        
        flag_str = get_flags_str(frag.flags, "MDE", spaces=True)

        sys.stdout.write('Frag {} (id={:<5},flag={:<3}): '.format(i,frag.id,flag_str))
        sys.stdout.write(' '*frag[IP].frag*8)
        print_non_ascii_string(str(frag[IP].payload))
        print

