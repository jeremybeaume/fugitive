#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import common


def list_evasions_under(evasion_name):
    """
    List evasion under a given name
    IPv4/Fragmentation returns all evasions inside this folder (an evasion_tree)
    a full evasion name returns the evasion itself
    """
    from ..net.evasions import evasion_tree #solve circular dependencies

    current_evasion_tree = evasion_tree
    if evasion_name is not None and evasion_name != '':
        folders = evasion_name.split("/")
        for f in folders:
            if f not in current_evasion_tree:
                common.print_error("Error : evasion '{}' not found".format(f))
                return None
            else:
                current_evasion_tree = current_evasion_tree[f]

    return current_evasion_tree
