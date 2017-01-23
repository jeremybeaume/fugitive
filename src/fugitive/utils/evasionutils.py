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
    from ..net.evasions import evasion_tree  # solve circular dependencies

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


def walk_evasion_tree(evasion_tree, current_evasion_folder, action, params=None, print_title=True):
    """
    Walk all evasions in the given tree
    launch action(evasion, current_evasion_folder, params) when an evasion is found
        current_Evasion_folder is an [] of the keys from the top of three

    a base current_Evasion_folder can be provided to be passed to actions (will append content to it),
    but it will not be printed

    title is printed with an indent of 4*len(current_evasion_folder)
    """

    if not isinstance(evasion_tree, dict):
        action(evasion_tree, current_evasion_folder, params)
    else:
        keys_list = sorted(evasion_tree.keys())
        # folder keys : all keys with dict value
        folder_keys = [x for x in keys_list if isinstance(
            evasion_tree[x], dict)]
        # evasion keys : all others keys
        evasion_keys = [x for x in keys_list if x not in folder_keys]

        # first launch all evasions in folder
        for key in evasion_keys:
            action(evasion_tree[key], current_evasion_folder, params)

        # then explore subfolders
        for key in folder_keys:
            if print_title:
                print(" " * (4 * len(current_evasion_folder)) +
                      "[+] " + str(key))
            walk_evasion_tree(evasion_tree[key], current_evasion_folder + [key],
                              action, params, print_title)


def print_evasion_tree(evasion_tree):
    def print_action(evasion, current_folder, params):
        print (" " * (4 * len(current_folder)) +
               "[" + evasion.get_id() + "] " + evasion.get_name())
    walk_evasion_tree(evasion_tree, [], action=print_action)
