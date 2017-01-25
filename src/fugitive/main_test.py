#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys

import utils


def run_tests(target, port, evasion_catalog, tester, outputfolder, verbose, do_check, check_only):

    if do_check:
        if not tester.check_test(target, port):
            sys.exit()
        print

    if not check_only:

        evasions_key_list = evasion_catalog.keys()
        evasions_key_list = sorted(evasions_key_list)
        current_folder = None

        for key in evasions_key_list:
            evasion = evasion_catalog[key]

            # print evasion name
            current_folder = utils.evasionutils.print_evasion_title_tree(
                evasion, current_folder)

            if outputfolder is not None:
                log_folder = outputfolder + "/" + evasion.evasion_folder
            else:
                log_folder = None

            name = evasion.get_id()

            logger = utils.testlogger.TestLogger(
                folder=log_folder, name=name, verbose=verbose)

            if verbose > 0:
                print  # ensure that log output on std out will be on new line

            logger.println(evasion.get_name(), verbose=5)
            logger.println(evasion.get_description(), verbose=5)
            logger.println("===================================", verbose=5)

            res, msg = tester.test(target, port, evasion, logger)

            logger.close()  # DO NOT FORGET !!

            if res:
                utils.print_success("SUCCESS")
            else:
                utils.print_error("FAIL : " + msg)
