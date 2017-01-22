#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys

import utils

#  iptables - A OUTPUT - p tcp - -tcp - flags RST RST - s 10.0.10.1 - j DROP


def run_tests(evasion_tree, tester, outputfolder, verbose, do_check, check_only):

    if do_check:
        if not tester.check_test():
            sys.exit()
        print

    if not check_only:
        params = {
            'verbose': verbose,
            'outputfolder': outputfolder,
            'tester': tester
        }
        utils.evasionutils.walk_evasion_tree(
            evasion_tree, [], action=test_walker_action, params=params, print_title=True)

"""
############# UTILS ##################
"""


def test_walker_action(evasion, current_folder, params):
    """ Test a single evasion """
    outputfolder = params['outputfolder']
    verbose = params['verbose']
    tester = params['tester']

    if outputfolder is not None:
        log_folder = outputfolder + "/" + "/".join(current_folder)
    else:
        log_folder = None

    name = evasion.get_id()

    logger = utils.testlogger.TestLogger(
        folder=log_folder, name=name, verbose=verbose)

    sys.stdout.write(" " * (4 * len(current_folder)) +
                     "[" + evasion.get_id() + "] " + evasion.get_name() + "  ")
    if verbose > 0:
        print  # ensure that log output on std out will be on new line

    res, msg = tester.test(evasion, logger)

    logger.close()  # DO NOT FORGET !!

    if res:
        utils.print_success("SUCCESS")
        return True
    else:
        utils.print_error("FAIL : " + msg)
        return False
