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

import json
import copy

class TestReport:
    """
    Store the tests resultst, and export them
    """

    def __init__(self):
        # dict result : dict{machine_name : [{tester:string, evasion_path:string, evasion_name:string, result:0|1, reason:string}]}
        self._results = {}

    def addResult(self, machine_name, tester, evasion_path, evasion_name, result, reason):
        machine_list = self._results.get(machine_name, [])

        res_dict = {'tester':tester, 'evasion_path':evasion_path, 'evasion_name':evasion_name, 'result':result, 'reason':reason}
        machine_list.append(res_dict)

        self._results[machine_name] = machine_list


    CSV_columns=['machine_name','tester','evasion_path','evasion_name','result','reason']
    def exportCSV(self, path):
        with open(path, 'w') as outfile:
            outfile.write(';'.join(TestReport.CSV_columns) + "\n")

            for machine, res_dict_list in self._results.iteritems():
                for res_dict in res_dict_list:
                    d = copy.deepcopy(res_dict)
                    d['machine_name'] = machine
                    # keys values in the CSV_columns order
                    val_list = [str(d[key]) for key in TestReport.CSV_columns]
                    outfile.write(';'.join(val_list) + "\n")

    def exportJSON(self, path):
        with open(path, 'w') as outfile:
            json.dump(self._results, outfile, indent=4,)