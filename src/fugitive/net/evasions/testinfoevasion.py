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

import baseevasion
import testdef.testdefutils


class TestInfoBasedEvasion(baseevasion.BaseEvasion):
    """
    Evasion using a test information dict
    see testdef package
    """

    def __init__(self, layer, test_info_dict, testid, outputid, reverse, evasion_type):

        self._testid = testid
        self._outputid = outputid
        self._reverse = reverse

        self._test_info = test_info_dict[testid]

        name = (self._test_info['name']
                + ' / Output ' + self._test_info['output'][self._outputid]
                + (' - Reversed' if self._reverse else '')
                + ' - ' + evasion_type)

        evasionid = (str(testid) + "." + str(outputid) +
                     "." + str(int(reverse)) + "." + evasion_type)

        baseevasion.BaseEvasion.__init__(
            self, name=name, evasionid=evasionid, layer=layer,
            evasion_type=evasion_type)

    def get_description(self):
        res = ""

        desc = self._test_info.get('description', None)
        if desc is None:
            desc = ""
        if desc != "":
            res += desc + "\n\n"

        # print input schema
        input = self._test_info['input']
        if self._reverse:
            input.reverse()
        res += "input : " + input[0] + "\n"
        for i in range(1, len(input)):
            res += "        " + input[i] + "\n"
        res += "output: " + self._test_info['output'][self._outputid] + "\n"

        return res

    @staticmethod
    def generate_evasion_list(test_info_dict, class_object, select_type=['bypass', 'inject']):
        evasion_list = class_object.evasion_list

        input_list = testdef.testdefutils.get_all_tests(test_info_dict)

        for t in input_list:
            if t[3] in select_type:
                evasion_list.append(class_object(testid=t[0], outputid=t[1],
                                                 reverse=t[2], evasion_type=t[3]))
