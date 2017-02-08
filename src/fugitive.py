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

    #### Main options ####
    main_group = parser.add_argument_group("Main options")
    main_group.add_argument("-c", metavar="CONFIG_FILE",
                            help="path to the configuration file")
    main_group.add_argument("-o", metavar="FOLDER",
                            help="Log (pcap & txt) output base directory")

    #### TEST OPTIONS ####
    test_group = parser.add_argument_group("Test options")
    test_group.add_argument("-t", "--target", metavar='NAME',
                            help="only test for this target")
    test_group.add_argument("--no-check", action="store_true",
                            help="Do not run connectivity check before testing")
    test_group.add_argument("--check-only", action="store_true",
                            help="Only run connectivity check, do not run tests")

    #### EVASION OPTIONS ####
    evasion_group = parser.add_argument_group("Evasions selection")
    evasion_group.add_argument("-e", metavar='EVASION_PATH',
                               help="Specify which evasion to use. Do not set to select all")
    evasion_group.add_argument("--list", action="store_true",
                               help="If set : only print evasions selected (-e option)")

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

    # load configuration file
    if args.c is None:
        fugitive.utils.print_error(
            "Configuration file is mandatory. Use -c option")
        sys.exit(1)

    try:
        config = fugitive.config.load_config_file(args.c)
    except Exception as e:
        fugitive.utils.print_error(
            "Could not load configuration file : " + str(e))
        sys.exit(1)

    target_list = config["targets"].keys()
    if args.target is not None:
        if not (args.target in target_list):
            fugitive.utils.print_error(
                "Target \"{}\" is not configured".format(args.target))
            sys.exit(1)
        else:
            target_list = [args.target]  # only select the one chosen

    for target_name in target_list:

        target_config = config["targets"][target_name]

        # FIXME
        tester = fugitive.tester.http_tester
        tester_config = config["tests"]["http"]

        outfolder = (args.o + "/" +
                     target_name) if (args.o is not None) else None

        print "\n## Testing {} ##\n".format(target_name)

        fugitive.main_test.run_tests(
            target_config=target_config,

            tester=tester,
            tester_config=tester_config,

            evasion_catalog=evasion_catalog,

            outputfolder=outfolder,
            verbose=args.v,

            do_check=(not args.no_check),
            check_only=args.check_only
        )
