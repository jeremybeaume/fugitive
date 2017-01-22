#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

def reverse_frag_list(frag_list, pre_frag=False, post_frag=False):
    """
    Reverse a list.
    If pre_frag is true, first element stays the first element
    If post_frag is true, last element stays
    """

    pre  = int(pre_frag)
    if not post_frag:
        post = len(frag_list)
    else:
        post = -1

    l = frag_list[:pre]

    middle = frag_list[pre:post]
    middle.reverse()
    l += middle

    l += frag_list[post:]

    return l;
