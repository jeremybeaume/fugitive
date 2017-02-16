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

import divideutils
from .... import utils


def make_fragment_evasion(
        payload, fragment_maker,
        frag_infos_list, evaded_area,
        signature_begin, signature_end,
        pre_frag_size=0, post_frag_size=0,
        offset_coef=1):
    """
    Makes a fragment list (using fragment_maker), by following the frag_info_list provided
    Divides the packets around the signature, and creates the appropriate fragments
    if signature_end < 0 :
        consider there is no signature, and simply divides the packets in equal parts

    payload        : payload to use for the fragments
    fragment_maker : see make_fragments function arguments help

    frag_infos_list   = list[frag_info] = [{'offset':int, 'content':[int]}] (offset in group unit)
    evaded_area = {'offset':int, 'size':int} (offset & size in group unit)

    signature_begin/end : position of the signature to be evaded (in data unit, included)

    pre/post_frag_size : if != 0 : create another frag at begin/end with minimal offset length of ...

    offset_coef : coef to pass from offset unit to data unit
        IPv4 : 1 offset unit = 8 data unit, so divisor is 8
    """

    # last possible offset value in the packet
    last_offset = int((len(payload) - 1) / offset_coef)
    number_offset = last_offset + 1

    # calculate evasion size : the max(offset + size) of all test fragments
    evasion_size = max([
        frag['offset'] + len(frag['content'])
        for frag in frag_infos_list  # get fragments for desired output
    ])

    if signature_end >= 0:
        ########## EVASION OF THE SIGNATURE #############

        # finding the first fragment offset containing the signature :
        sign_first_offset = int(signature_begin / offset_coef)
        # finding the last one :
        sign_last_offset = int(signature_end / offset_coef)

        evaded_offset = evaded_area['offset']
        evaded_size = evaded_area['size']

        # check the last actual payload content group
        # ie, the last offset in the evasion with actual payload content
        last_actual_content_offset = max([
            # find last not 0 values offset, or -1 if all 0
            max([-1] + [frag_infos['offset'] + index
                        for (index, val) in enumerate(frag_infos['content']) if val != 0])
            for frag_infos in frag_infos_list
        ])

        if last_actual_content_offset < 0:
            # no fragment takes actual payload content ? seriously ?
            raise ValueError(
                "Incorrect fragment_definition : no payload content taken")

        if last_actual_content_offset < evasion_size - 1:
            # some offset at the end takes no payload data : this evasion injects a fragment at the end
            # The real payload is for example 2 groups long
            # But some equipment might takes in account a third group
            if post_frag_size > 0:
                # no idea what it means : we are injectinf data at the end here
                # ...
                raise ValueError(
                    "Incorrect fragmentation definition : end data injection, but post_size ?")
            # divide equally, with pre_fragment if needed :
            (pre_size, frag_sizes) = divideutils.divide_area(size=number_offset, number=last_actual_content_offset + 1,
                                                             fixed_size_element=pre_frag_size)
            # the injected groups at the end takes the same size as the last actual
            # payload fragment
            end_injected_group_size = [frag_sizes[-1]] * \
                (evasion_size - 1 - last_actual_content_offset)
            group_sizes = [pre_size] + frag_sizes + \
                end_injected_group_size + [0]
        else:

            # division of the offset space between the fragment groups
            # to match signature with evasion capacity
            group_sizes = divideutils.compute_frag_size(
                payload_size=number_offset,
                pre_size=pre_frag_size,
                post_size=post_frag_size,
                evaded_offset=evaded_offset,
                evaded_size=evaded_size,
                evasion_size=evasion_size,
                sign_begin=sign_first_offset,
                sign_end=sign_last_offset)

    else:  # signature_end < 0:
        # INJECTION ATTACK : simply fragment equally
        # takes minimum sizes for pre and post fragments

        (fixe_size, frag_sizes) = divideutils.divide_area(size=number_offset - pre_frag_size - post_frag_size,
                                                          number=evasion_size,
                                                          fixed_size_element=0)
        group_sizes = [pre_frag_size] + frag_sizes + [post_frag_size]

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

    # add first fragment
    if group_sizes[0] > 0:
        generated_content = payload[:group_sizes[0] * offset_coef]
        frag_list.append(fragment_maker(
            offset=0, payload=generated_content, frag_info=None))

    for frag_info in frag_infos_list:
        # offset : sum the sizes of all preceding columns
        # 0 if pre_size column
        offset = sum(group_sizes[0: 1 + frag_info['offset']])
        # generate content :
        content_list = frag_info['content']
        generated_content = ""
        current_offset = offset
        for i in range(0, len(content_list)):
            current_group_size = group_sizes[1 + i + frag_info['offset']]
            if content_list[i] == 0:
                generated_content += "-" * (current_group_size * offset_coef)
            else:
                # take packet content
                generated_content += payload[
                    current_offset * offset_coef: (current_offset + current_group_size) * offset_coef]

            current_offset += current_group_size

        frag_list.append(fragment_maker(
            offset=offset, payload=generated_content, frag_info=frag_info))

    if group_sizes[-1] > 0:
        # add last fragment
        offset = sum(group_sizes[0:-1])
        generated_content = payload[offset * offset_coef:]
        frag_list.append(fragment_maker(
            offset=offset, payload=generated_content, frag_info=None))

    return frag_list
