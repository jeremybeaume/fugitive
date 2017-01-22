#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys


def compute_frag_size(payload_size, pre_size, post_size,
                      evaded_offset, evaded_size, evasion_size,
                      sign_begin, sign_end
                      ):
    """
    Compute fragment size :
    payload size is the size of payload, in fragment unit
    pre_size : minimal size to put before the evasion, the evasion wont go there (in frag unit)
    post_size : idem after
    evaded_ofset : offset of the evaded area (in group unit)
    evaded_size : size of the evaded area (in group unit)
    evasion_size : size of the evasion area (in group unit)
    sign_begin : begin of the signature (in frag unit)
    sign_end : end of the signature (in frag unit)

    Frag unit is the quantity of data :
    for TCP, it means 1 byte, as TCP can send bytes 1 by 1
    for IP, it means 8 bytes, a fragment can not be less than 8 bytes long

    Group unit : Consider this representation :
    | A B|
       |C D|
    this group is long of 3 group unit, the overlapping area is at group offset 1, and 1 group long

    The algorithm will try to match the evaded area will the whole signature

               < evaded_offset = 2 >
    | pre_size |   A   |     B     |    evaded       | C | post_size |
                                   < evaded_size = 1 >
               <        evasion_size = 4                 >

    returns a list with all the fragment SIZES (WARNING HERE !!)
    index[0]  is final pre_size
    from [1 : 1 + evasion_size] : frag unit SIZE of the groups
    index[-1] is final post_size
    """

    evasion_post_size = (evasion_size - evaded_offset - evaded_size)
    # size needed by the evasion after the evaded area (B area)

    # Check there is enough data (consider all fragment size to 8)
    if payload_size < evasion_size + pre_size + post_size:
        raise IOError("Payload too small for evasion")

    # signature is in the begining of the payload :
    # so can not do if the end of the signature is before the minimum evaded
    # area
    earliest_evasion_begin = pre_size + evaded_offset
    # the minimal point where evasion can begin
    if sign_end < earliest_evasion_begin:
        # the evasion does not permit to evade a fragment with too low fragment
        raise IOError("Can not evade content : too in the begining")

    # signature is at the end of the payload
    # The evasions need size after the end of the evaded area
    # Can not if the begin of the signature is after the maximum evaded area
    # -1 for the actual last fragment post position
    latest_evasion_end = payload_size - 1 - post_size - evasion_post_size
    # highest position where the evasion area can end
    if latest_evasion_end < sign_begin:
        raise IOError("Can not evade content : too at the end")

    # calculate the best begin for the evasion zone (need to evade at leaast
    # one unit of signature)
    if pre_size != 0 or evaded_offset != 0:
        evasion_area_begin = min(
            # earliest begin, at worst sign_end (checked before)
            max(sign_begin, earliest_evasion_begin),
            latest_evasion_end - evaded_size + 1  # actual start
        )
    else:
        # there is no offset or pre_size : evasion start at 0 !
        evasion_area_begin = 0

    if post_size != 0 or evasion_post_size != 0:
        evasion_area_end = max(
            min(sign_end, latest_evasion_end),  # at worst
            earliest_evasion_begin + evaded_size - 1)
    else:
        # not post fragment, evasions end at the end
        evasion_area_end = payload_size - 1

    # divide the area before the evasion
    pre_fragment_size, pre_evade_frag_size = divide_area(
        evasion_area_begin, evaded_offset, pre_size)
    post_fragment_size, post_evade_frag_size = divide_area(payload_size - 1 - evasion_area_end,
                                                           evasion_post_size, post_size)
    plop, evade_area_frag_sizes = divide_area(
        evasion_area_end - evasion_area_begin + 1, evaded_size, 0)

    result = ([pre_fragment_size] + pre_evade_frag_size
              + evade_area_frag_sizes
              + post_evade_frag_size + [post_fragment_size])

    # debug
    #_print_division(result, payload_size, pre_size, post_size,
    #        evaded_offset, evaded_size, evasion_size,
    #        sign_begin, sign_end)

    return result


def divide_area(size, number, fixed_size_element):
    """ Divide an area equally between number occupant, with another
    occupant having a minimal size of fixed_size_element
    return (fixed_size_element_size, element_size_list)
    """
    element_size_list = [0] * number
    fixed_size = 0

    if number == 0:
        return (size, [])  # all for the fixed_size_element
    else:
        if fixed_size_element == 0:
            # divides equally between the elements
            element_size, rest = _module_divide(size, number)
        else:
            # tries to divide equally with pre-fragment
            element_size, rest = _module_divide(size, number + 1)
            if element_size + rest >= fixed_size_element:
                #division is ok
                fixed_size = element_size + rest  # takes the rest
                rest = 0
            else:
                # pre_size is too big for equality
                fixed_size = fixed_size_element
                # divide the rest equaly
                element_size, rest = _module_divide(size - fixed_size, number)

        # save the fragment sizes
        for i in range(0, number):
            element_size_list[i] = element_size
        # add the rest t the first fragment
        element_size_list[0] += rest

        return (fixed_size, element_size_list)


def _module_divide(a, b):
    return (a / b, a % b)


def _print_division(l, payload_size, pre_size, post_size,
                    evaded_offset, evaded_size, evasion_size,
                    sign_begin, sign_end):
    for i in range(0, payload_size):
        sys.stdout.write("| {} ".format(i))
    print

    for i in range(l[0]):
        sys.stdout.write("|Pre")
    for i in range(1, 1 + evaded_offset):
        for j in range(0, l[i]):
            sys.stdout.write("| A ")
    for i in range(1 + evaded_offset, 1 + evaded_offset + evaded_size):
        for j in range(0, l[i]):
            sys.stdout.write("| E ")
    for i in range(1 + evaded_offset + evaded_size, 1 + evasion_size):
        for j in range(0, l[i]):
            sys.stdout.write("| B ")
    for i in range(l[-1]):
        sys.stdout.write("|Pos")
    print

    for i in range(0, sign_begin):
        sys.stdout.write("|   ")
    for i in range(sign_begin, sign_end + 1):
        sys.stdout.write("| S ")
    for i in range(sign_end, payload_size):
        sys.stdout.write("|   ")
    print


# compute_frag_size(payload_size=11, pre_size=1, post_size=0,
#        evaded_offset=0, evaded_size=1, evasion_size=2,
#        sign_begin=3, sign_end=7
#        )
