#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys

import utils

#  iptables - A OUTPUT - p tcp - -tcp - flags RST RST - s 10.0.10.1 - j DROP


def run_tests(evasion_name, tester, outputfolder, verbose):

    evasion_to_test = utils.evasionutils.list_evasions_under(evasion_name)

    if not tester.check_test():
        sys.exit()

    print
    test_all_evasion(tester, evasion_to_test, [], outputfolder, verbose)

"""
############# UTILS ##################
"""


def test_all_evasion(tester, evasion_tree, current_evasion_folder, outputfolder, verbose):
    """ Test all evasion in an evasion tree """

    if not isinstance(evasion_tree, dict):
        launch_test(tester, evasion_tree, [], outputfolder, verbose)
    else:
        keys_list = sorted(evasion_tree.keys())
        # folder keys : all keys with dict value
        folder_keys = [x for x in keys_list if isinstance(
            evasion_tree[x], dict)]
        # evasion keys : all others keys
        evasion_keys = [x for x in keys_list if x not in folder_keys]

        # first launch all evasions in folder
        for key in evasion_keys:
            launch_test(tester, evasion_tree[key],
                        current_evasion_folder, outputfolder, verbose)

        # then explore subfolders
        for key in folder_keys:
            print(" " * (4 * len(current_evasion_folder)) + "[+] " + str(key))
            test_all_evasion(tester,
                             evasion_tree[key], current_evasion_folder + [key],
                             outputfolder, verbose)


def launch_test(tester, evasion, current_folder, outputfolder, verbose):
    """ Test a single evasion """
    log_folder = outputfolder + "/" + "/".join(current_folder)
    name = evasion.get_id()

    logger = utils.testlogger.TestLogger(
        folder=log_folder, name=name, verbose=verbose)

    sys.stdout.write(" " * (4 * len(current_folder)) +
                     "[" + evasion.get_id() + "] " + evasion.get_name() + "  ")

    res, msg = tester.test(evasion, logger)

    logger.close()  # DO NOT FORGET !!

    if res:
        utils.print_success("SUCCESS")
        return True
    else:
        utils.print_error("FAIL : " + msg)
        return False
