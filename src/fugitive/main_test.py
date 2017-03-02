#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Fugitive : Network evasion tester
# Copyright (C) 2017 Jérémy BEAUME (jeremy [dot] beaume (a) protonmail [dot] com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys

import utils


def run_tests(testreport, target_name, target_config, tester, tester_config, evasion_catalog, outputfolder, verbose, do_check, check_only):

    if do_check:
        if not tester.check_test(target_config, tester_config):
            return None
        print

    if not check_only:

        evasions_key_list = sorted(evasion_catalog.keys())
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

            res, msg = tester.test(
                target_config, tester_config, evasion, logger)

            logger.close()  # DO NOT FORGET !!

            if res:
                utils.print_success("SUCCESS")
            else:
                utils.print_error("FAIL : " + msg)

            testreport.addResult(machine_name=target_name,
                tester=tester.name,
                evasion_path=evasion.evasion_folder + '/' + evasion.get_id(),
                evasion_name=evasion.get_name(),
                result=(1 if res else 0),
                reason=msg)
