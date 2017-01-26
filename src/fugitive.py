#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

# remove scapy warninng
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
import sys
import argparse

import fugitive

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Fugitiv : evade detection")

    #### TEST OPTIONS ####
    test_group = parser.add_argument_group("Test options")
    test_group.add_argument("-t", "--target", metavar='TARGET:PORT',
                            help="Target of the test (ip_or_dns:port)")
    test_group.add_argument("--no-check", action="store_true",
                            help="Do not run connectivity check before testing")
    test_group.add_argument("--check-only", action="store_true",
                            help="Only run connectivity check, do not run tests")

    # test_group.add_argument("-m", metavar="TEST METHOD",
    #                        choices=["http"],
    #                        help="test method")
    # test_group.add_argument("-c", metavar="CONFIG FILE",
    #                        help="path to a test configuration file (TODO)")

    #### EVASION OPTIONS ####
    evasion_group = parser.add_argument_group("Evasions selection")
    evasion_group.add_argument("-e", metavar='EVASION_PATH',
                               help="Specify which evasion to use. Do not set to select all")
    evasion_group.add_argument("--list", action="store_true",
                               help="If set : only print evasions selected (-e option)")

    #### OUTPUT OPTIONS ####
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", metavar="FOLDER",
                              help="Log (pcap & txt) output base directory")

    #### OTHER ARGUMENTS ####
    parser.add_argument("-v", action="count", default=0,
                        help="verbose level")

    args = parser.parse_args()

    # parse evasions options

    # option e : get evasion list
    folder = args.e
    if folder is not None:
        if folder[:1] == '/':  # remove first / if one
            folder = folder[1:]
        if folder[-1:] == '/':  # remove last / if one
            folder = folder[:-1]
    evasion_catalog = fugitive.utils.evasionutils.list_evasions_under(folder)
    if evasion_catalog is None:
        sys.exit(1)

    # if flag --list is True : simply print the result and leave
    # Overwrite others arguments do to ... nothing =)
    if args.list:

        fugitive.utils.evasionutils.print_evasion_catalog(evasion_catalog)
        sys.exit(1)

    if args.target is None:
        print "Error : target required to run test (use -t TARGET:PORT)"
        sys.exit(1)
    else:
        try:
            target, port = fugitive.net.socket.sockutils.parse_target_port(
                args.target)
        except Exception as e:
            print str(e)
            sys.exit(1)

    fugitive.main_test.run_tests(
        target=target,
        port=port,
        evasion_catalog=evasion_catalog,
        tester=fugitive.test.http_evasion_tester,
        outputfolder=args.o,
        verbose=args.v,
        do_check=(not args.no_check),
        check_only=args.check_only
    )
