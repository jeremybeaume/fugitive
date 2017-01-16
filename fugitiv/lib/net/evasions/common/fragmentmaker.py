#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import divideutils

def make_fragment_evasion(
            payload, fragment_maker,
            frag_infos_list, evaded_area,
            signature_begin, signature_end,
            pre_frag_size = 0, post_frag_size = 0,
            offset_coef = 1):
    """
    payload        : payload to use for the fragments
    fragment_maker : see make_fragments function arguments help

    frag_infos_list   = list[frag_info] = [{'offset':int, 'content':[int]}] (offset in group unit)
    evaded_area = {'offset':int, 'size':int} (offset & size in group unit)

    signature_begin/end : position of the signature to be evaded (in data unit, included)

    pre/post_frag_size : if != 0 : create another frag at begin/end with minimal offset length of ...

    offset_coef : coef to pass from offset unit to data unit
        IPv4 : 1 offset unit = 8 data unit, so divisor is 8
    """

    # finding the first fragment offset containing the signature :
    sign_first_offset = int(signature_begin/offset_coef)
    # finding the last one :
    sign_last_offset = int(signature_end/offset_coef)

    last_offset = int((len(payload)-1) /offset_coef) #last possible offset value in the packet
    number_offset = last_offset + 1

    evaded_offset = evaded_area['offset']
    evaded_size   = evaded_area['size']
    # calculate evasion size : the max(offset + size) of all test fragments
    evasion_size = max([
            frag['offset'] + len(frag['content'])
            for frag in frag_infos_list #get fragments for desired output
        ])

    # division of the offset space between the fragment groups
    # to match signature with evasion capacity
    group_sizes = divideutils.compute_frag_size(
        payload_size  = number_offset,
        pre_size      = pre_frag_size,
        post_size     = post_frag_size,
        evaded_offset = evaded_offset,
        evaded_size   = evaded_size,
        evasion_size  = evasion_size,
        sign_begin    = sign_first_offset,
        sign_end      = sign_last_offset)

    # now makes the fragments
    return make_fragments(payload, fragment_maker, frag_infos_list, group_sizes, offset_coef)


def make_fragments(payload, fragment_maker, frag_infos_list, group_sizes, offset_coef):
    """
    *Generates fragment from a payload, with provided group definition and sizes*

    payload : payload to use for the fragment data

    fragment_maker : function(offset, payload, frag_info)
                        offset : fragment offset
                        payload : fragment data
                        frag_info : associated frag_info (None for pre and post fragments)
                                    if frag_info is None and offset=0 : this is the Pre-fragment
                                    if frag_info is None and offset>0 : this is the post-fragment
                        returns the scapy packet for this fragment

    frag_infos_list   = list[frag_info] = [{'offset':int, 'content':[int]}] (offset in group unit)

    group_sizes = array of group sizes (len = number of frag_info different groups + 2)
                 index[0]  : initial fragment size
                 index[-1] : last fragment size

    offset_coef : coef to pass from offset unit to data unit
                   IPv4 : 1 offset unit = 8 data unit, so divisor is 8

    *Example:*

    |A B|
      |C D|

    => frag_info has 3 groups (A, BC, D)
    the group_sizes list len is 5 to be able to make :
    |Pre-fragment|
                 |A B|
                   |C D|
                       |Post-fragment| 
    """

    frag_list = []
    
    #add first fragment
    if group_sizes[0] >0 :
        generated_content = payload[:group_sizes[0]*offset_coef]
        frag_list.append(fragment_maker(offset=0, payload=generated_content, frag_info=None))

    for frag_info in frag_infos_list:
        # offset : sum the sizes of all preceding columns
        # 0 if pre_size column
        offset = sum(group_sizes[0 : 1 + frag_info['offset']])
        # generate content :
        content_list = frag_info['content']
        generated_content = ""
        current_offset = offset
        for i in range(0,len(content_list)):
            current_group_size = group_sizes[1 + i + frag_info['offset']]
            if content_list[i] == 0:
                generated_content += "-"*(current_group_size*offset_coef)
            else:
                #take packet content
                generated_content += payload[
                                  current_offset*offset_coef
                                : (current_offset + current_group_size)*offset_coef ]

            current_offset += current_group_size

        frag_list.append(fragment_maker(offset=offset, payload=generated_content, frag_info=frag_info))

    #add last fragment
    offset = sum(group_sizes[0:-1])
    generated_content = payload[offset*offset_coef:]
    frag_list.append(fragment_maker(offset=offset, payload=generated_content, frag_info=None))

    return frag_list