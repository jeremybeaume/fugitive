#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys
import fugitiv

verbose = 0

#  iptables - A OUTPUT - p tcp - -tcp - flags RST RST - s 10.0.10.1 - j DROP
if not fugitiv.test.http_evasion_tester.check_test():
    sys.exit()

logger = fugitiv.utils.testlogger.TestLogger(
    folder=None, name=None, verbose=verbose)


def launch_test(evasion, indent):
    sys.stdout.write(" " * (4 * indent) +
                     "[" + evasion.get_id() + "] " + evasion.get_name() + "  ")
    res, msg = fugitiv.test.http_evasion_tester.test(evasion, logger)
    if res:
        fugitiv.utils.print_success("SUCCESS")
    else:
        fugitiv.utils.print_error("FAIL : " + msg)


def test_all_evasion(evasion_tree, current_folder=[]):
    keys_list = sorted(evasion_tree.keys())
    # folder keys : all keys with dict value
    folder_keys = [x for x in keys_list if isinstance(evasion_tree[x], dict)]
    # evasion keys : all others keys
    evasion_keys = [x for x in keys_list if x not in folder_keys]

    for key in evasion_keys:
        launch_test(evasion_tree[key], len(current_folder))

    for key in folder_keys:
        print(" " * (4 * len(current_folder)) + "[+] " + str(key))
        test_all_evasion(evasion_tree[key], current_folder + [key])

test_all_evasion(fugitiv.net.evasions.evasion_tree)
