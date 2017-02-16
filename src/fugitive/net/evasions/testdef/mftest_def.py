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
*Evasion exploiting the MF IPv4 Flag*

Does it mean that no more packet are coming ?
Or does it mean that this fragment in the last in term of offset ?

"""
mf_flag_evasion = {
    0: {
        # defautl simple case
        'name': 'Base case (A,B,C, C no MF)',
        'description': 'Base case : evasion should never work !',
        'input': [
            '|A-MF|          ',
            '     |B-MF|     ',
            '          |C-  |'
        ],
        'output': ['|ABC|'],
        'frags': [
            # output |ABC|
            [{'offset': 0, 'content': [1], 'flags':'MF'},
             {'offset': 1, 'content': [1], 'flags':'MF'},
             {'offset': 2, 'content': [1], 'flags':None}]
        ],
        'evaded': {'offset': 1, 'size': 1},  # no real evasions
        'reverse': True,
        'type': ['bypass', 'inject']
    },

    1: {
        # C fragment should be ignored most probably
        'name': 'Post defrag framgent (A,B,C - B no MF)',
        'input': [
            '|A-MF|          ',
            '     |B-  |     ',
            '          |C-MF|'
        ],
        'output': ['|AB|', '|ABC|'],
        'frags': [
            # output |AB|
            [{'offset': 0, 'content': [1], 'flags':'MF'},
             {'offset': 1, 'content': [1], 'flags':None},
             {'offset': 2, 'content': [0], 'flags':'MF'}],
            # output |ABC|
            [{'offset': 0, 'content': [1], 'flags':'MF'},
             {'offset': 1, 'content': [1], 'flags':None},
             {'offset': 2, 'content': [1], 'flags':'MF'}]
        ],
        'evaded': {'offset': 2, 'size': 1},
        'reverse': False,
        'type': ['bypass', 'inject']
    },

    2: {
        'name': 'Middle offset-last arrived (A,C,B - B no MF)',
        'description': 'Some implementation may use all fragments, others may use fragment until no MF flag',
        'input': [
            '|A-MF|          ',
            '          |C-MF|',
            '     |B-  |     ',
        ],
        'output': ['|AB|', '|ABC|'],
        'frags': [
            # output |AB|
            [{'offset': 0, 'content': [1], 'flags':'MF'},
             {'offset': 2, 'content': [0], 'flags':'MF'},
             {'offset': 1, 'content': [1], 'flags':None}],
            # output |ABC|
            [{'offset': 0, 'content': [1], 'flags':'MF'},
             {'offset': 2, 'content': [1], 'flags':'MF'},
             {'offset': 1, 'content': [1], 'flags':None}]
        ],
        'evaded': {'offset': 2, 'size': 1},
        'reverse': False,
        'type': ['bypass', 'inject']
    },

    3: {
        'name': 'First offset appears not fragmented (B,A - A no MF)',
        'description': 'Checks if a shorcut is made for packet appearing non fragmented',
        'input': [
            '     |B-MF|',
            '|A-  |     '
        ],
        'output': ['|A|', '|AB|'],
        'frags': [
            # output |A| #FIXEME : Protégé par le header TCP et content_length
            [{'offset': 1, 'content': [0], 'flags':'MF'},
             {'offset': 0, 'content': [1], 'flags':None}],
            # output |ABC|
            [{'offset': 1, 'content': [1], 'flags':'MF'},
             {'offset': 0, 'content': [1], 'flags':None}]
        ],
        'evaded': {'offset': 1, 'size': 1},
        'reverse': False,
        'type': ['bypass', 'inject']
    },

    4: {
        'name': 'Double no-MF (A,C,B - C,B no MF)',
        'description': 'Which no mf flag counts ? the last in offset order ? the last received ?',
        'input': [
            '|A-MF|          ',
            '          |C-  |',
            '     |B-  |     ',
        ],
        'output': ['|AB|', '|ABC|'],
        'frags': [
            # output |AB|
            [{'offset': 0, 'content': [1], 'flags':'MF'},
             {'offset': 2, 'content': [0], 'flags':None},
             {'offset': 1, 'content': [1], 'flags':None}],
            # output |ABC|
            [{'offset': 0, 'content': [1], 'flags':'MF'},
             {'offset': 2, 'content': [1], 'flags':None},
             {'offset': 1, 'content': [1], 'flags':None}]
        ],
        'evaded': {'offset': 2, 'size': 1},
        'reverse': False,
        'type': ['bypass', 'inject']
    }
}
