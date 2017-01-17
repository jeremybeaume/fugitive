#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

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
        'input': [
            '|A|'
        ],
        'output': ['|A|'],
        'frags': [
            # output |A|
            [{'offset': 0, 'content': [1]}]
        ],
        'reverse': False,
        'evaded': {'offset': 0, 'size': 1}
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
        'evaded': {'offset': 0, 'size': 1}
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
        'reverse': True,
        'evaded': {'offset': 1, 'size': 1}
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
        'reverse': True,
        'evaded': {'offset': 1, 'size': 1}
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
        'reverse': True,
        'evaded': {'offset': 1, 'size': 1}
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
        'reverse': False,
        'evaded': {'offset': 0, 'size': 1}
    }
}
