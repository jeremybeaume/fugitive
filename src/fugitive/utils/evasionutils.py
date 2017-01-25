#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import sys


def list_evasions_under(evasion_name):
    """
    List evasion under a given name
    IPv4/Fragmentation returns all evasions inside this folder (an evasion_tree)
    a full evasion name returns the evasion itself

    make sure to iterate the evasion_catalog sorted by its keys !
    """
    from ..net.evasions import evasion_catalog  # solve circular dependencies

    if evasion_name is None:
        return evasion_catalog

    res_dict = {key: evasion_catalog[
        key] for key in evasion_catalog.keys() if key.startswith(evasion_name)}

    return res_dict


def print_evasion_title_tree(evasion, current_tree=None):
    """
    Print evasion as folders
    evasion is current evasion to be printed
    current_Tree is the current value for the returned folder tree
    if current_tree is IPv4, Fragementation, Overlap
    and evasion folder is IPV4/Fragmentation/MF :
    will print MF title, and then evasion name

    How to use :
    current_tree = print_evasion_title(evasion, current_tree)
    print whatever you want (no newline is printed after evasion name)

    make sure to iterate the evasion_catalog sorted by its keys !
    """

    if current_tree is None:
        current_tree = []

    folder = evasion.evasion_folder.split('/')

    # get current common indentation
    i = 0
    while(i < len(current_tree) and i < len(folder) and current_tree[i] == folder[i]):
        i += 1

    # print missing titles
    for j in range(i, len(folder)):
        print " " * (j * 4) + "[+] " + folder[j]

    # print evasion name, without newline
    sys.stdout.write(" " * len(folder) * 4 +
                     "[" + evasion.get_id() + "] " + evasion.get_name() + " ")

    return folder


def print_evasion_catalog(evasion_catalog):
    evasions_key_list = evasion_catalog.keys()
    evasions_key_list = sorted(evasions_key_list)
    current_folder = None

    for key in evasions_key_list:
        evasion = evasion_catalog[key]

        # print evasion name
        current_folder = print_evasion_title_tree(
            evasion, current_folder)
        # no newline is printed !!
        print
