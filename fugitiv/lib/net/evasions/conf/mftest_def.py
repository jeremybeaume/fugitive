#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

"""
*Evasion exploiting the MF IPv4 Flag*

Does it mean that no more packet are coming ?
Or does it mean that this fragment in the last in term of offset ?

"""
mf_flag_evasion = {
    0: {
        # defautl simple case
        'name': 'Base case (A,B,C, C no MF)',
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
        'reverse': True
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
        'reverse': False
    },

    2: {
        # C fragment might be used, depends on MF signification
        'name': 'Middle offset-last arrived (A,C,B - B no MF)',
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
        'reverse': False
    },

    3: {
        # A Fragment appears not fragmented, but ....
        'name': 'First offset not fragmented ? (B,A - A no MF)',
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
        'reverse': False
    },

    4: {
        # C fragment might be used, depends on MF signification
        'name': 'Double no-MF (A,C,B - C,B no MF)',
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
        'reverse': False
    },

    # TODO : Overlapping fragment with MF flag : EVIIIIL
    # |A B| (MF)
    # |C|   (  )
}
