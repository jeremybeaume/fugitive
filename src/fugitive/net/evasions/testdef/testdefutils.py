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


def get_all_tests(test_def_dict):
    """
    Get all possible evasion parameters for a test_def_dict
    returns a list[(testid, outputid, reverse, type)]
    """
    test_list = []
    for test_id in test_def_dict.keys():
        test_info = test_def_dict[test_id]

        # get all tests for the test_info
        type_l = test_info.get('type', [])
        if len(type_l) == 0:
            raise ValueError(
                "Parsing evasion test definition : 'type' is not defined or empty ")

        for evasion_type in type_l:
            for outputid in range(0, len(test_info['output'])):
                test_list.append((test_id, outputid, False, evasion_type))
                if test_info['reverse']:
                    test_list.append(
                        (test_id, outputid, True, evasion_type))
    return test_list
