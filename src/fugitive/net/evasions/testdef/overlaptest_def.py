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

"""
*Overlap evasions definition*

The overlap test should breaks the packet around the signature :
DATA | SIGNATURE | DATA

IE : the test :
|A|junk|
  |  B |C|

Gives the fragments :
|DATA|
     |A|junk|
       |  B |C|
              |DATA|

That way :
IPv4 : All fragment have MF flag except the last one (both in offset and time)
"""

overlap_evasion = {
    0: {
        'name': 'Base fragmentation case',
        'description': 'Base case : evasion should never work !',
        'input': [
            '|A|'
        ],
        'output': ['|A|'],
        'frags': [
            # output |A|
            [{'offset': 0, 'content': [1]}]
        ],
        'reverse': False,
        'evaded': {'offset': 0, 'size': 1},
        'type': ['bypass', 'inject']
    },
    1: {
        'name': 'Begin-included',
        'input': [
            '|A B|',
            '|C|  '
        ],
        'output': ['|AB|', '|CB|'],
        'frags': [
            # output |AB|
            [{'offset': 0, 'content': [1, 1]},
             {'offset': 0, 'content': [0]}],
            # output |CB|
            [{'offset': 0, 'content': [0, 1]},
             {'offset': 0, 'content': [1]}]
        ],
        'reverse': True,
        'evaded': {'offset': 0, 'size': 1},
        'type': ['bypass', 'inject']
    },
    2: {
        'name': 'Middle-included',
        'input': [
            '|A B C|',
            '  |D|  '
        ],
        'output': ['|ABC|', '|ADC|'],
        'frags': [
            # output |ABC|
            [{'offset': 0, 'content': [1, 1, 1]},
             {'offset': 1, 'content': [0]}],
            # output |ADC|
            [{'offset': 0, 'content': [1, 0, 1]},
             {'offset': 1, 'content': [1]}]
        ],
        'evaded': {'offset': 1, 'size': 1},
        'reverse': True,
        'type': ['bypass', 'inject']
    },
    3: {
        'name': 'End-included',
        'input': [
            '|A B|',
            '  |C|'
        ],
        'output': ['|AB|', '|AC|'],
        'frags': [
            # output |AB|
            [{'offset': 0, 'content': [1, 1]},
             {'offset': 1, 'content': [0]}],
            # output |AC|
            [{'offset': 0, 'content': [1, 0]},
             {'offset': 1, 'content': [1]}],
        ],
        'evaded': {'offset': 1, 'size': 1},
        'reverse': True,
        'type': ['bypass', 'inject']
    },
    4: {
        'name': 'One-Another overlap',
        'input': [
            '|A B|  ',
            '  |C D|'
        ],
        'output': ['|ABD|', '|ACD|'],
        'frags': [
            # output |ABD|
            [{'offset': 0, 'content': [1, 1]},
             {'offset': 1, 'content': [0, 1]}],
            # output |ACD|
            [{'offset': 0, 'content': [1, 0]},
             {'offset': 1, 'content': [1, 1]}],
        ],
        'evaded': {'offset': 1, 'size': 1},
        'reverse': True,
        'type': ['bypass', 'inject']
    },
    5: {
        'name': 'Fragment rewrite',
        'input': [
            '|A|',
            '|B|'
        ],
        'output': ['|A|', '|B|'],
        'frags': [
            # output |AB|
            [{'offset': 0, 'content': [1]},
             {'offset': 0, 'content': [0]}],
            # output |CB|
            [{'offset': 0, 'content': [0]},
             {'offset': 0, 'content': [1]}],
        ],
        'evaded': {'offset': 0, 'size': 1},
        'reverse': True,
        'type': ['bypass', 'inject']
    }
}
