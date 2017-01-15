#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

"""
** General Incontentation for IPv4 fragmentation evasions **

Dict of IPv4 fragmentation tests :
base : dict(test_id=>test_infos)

test_infos = dict :
    'input'  : array of string, to be printed vertically, in the list order
               displays the content of the packets sent
    'output' : array of string, corresponding to possible outputs defragmentation
    'frags'  : array of fragements array to be sent, for each output,
               to get correct defragmentation for the considered output,
               and junk for the others output
    'reverse': Do the test with fragment sent in other order
    'evaded' : {'offset':int, 'size':int} : part of the described evasion that is obfuscated

fragment : dict :
    'offset' : offset from the begining of signature area
               (one fragment must at least have offset = 0)
    'content'   : array of int for content
               0 means take content of the input packet
               1 means generate junk for this part

The sizes and offset are an indication :
the actual fragment size and offset may be a multiple of thoses values.
"""


"""
Specific Infos for overlap_test :

The overlap test breaks the packet around the signature :
DATA | SIGNATURE | DATA

So there is one fragment with begining test data
it uses the test incontentation to make overlaping fragment around signature
the last fragment is dinal data.

IE : the test :
|A|junk|
  |  B |C|

Gives the fragments :
|DATA|
     |A|junk|
       |  B |C|
              |DATA|

The MF flag is not set on the overlaping fragments
"""

overlap_evason={
    0 : {
        'input' : [
            '|A B|',
            '|C|  '
        ],
        'output':['|AB|', '|CB|'],
        'frags':[
            #output |AB|
            [ {'offset':0, 'content':[1, 1]},
              {'offset':0, 'content':[0   ]} ],
            #output |CB|
            [ {'offset':0, 'content':[0, 1]},
              {'offset':0, 'content':[1   ]} ]
        ],
        'reverse':True,
        'evaded':{'offset':0, 'size':1}
    },
    1 : {
       'input' : [
            '|A B C|',
            '  |D|  '
        ],
        'output':['|ABC|', '|ADC|'],
        'frags':[
            #output |ABC|
            [ {'offset':0, 'content':[1, 1, 1]},
              {'offset':1, 'content':[   0   ]} ],
            #output |ADC|
            [ {'offset':0, 'content':[1, 0, 1]},
              {'offset':1, 'content':[   1   ]} ]
        ],
        'reverse':True,
        'evaded':{'offset':1, 'size':1}
    },
    2 : {
        'input' : [
            '|A B|',
            '  |C|'
        ],
        'output':['|AB|', '|AC|'],
        'frags':[
            #output |AB|
            [ {'offset':0, 'content':[1, 1]},
              {'offset':1, 'content':[   0]} ],
            #output |AC|
            [ {'offset':0, 'content':[1, 0]},
              {'offset':1, 'content':[   1]} ],
        ],
        'reverse':True,
        'evaded':{'offset':1, 'size':1}
    },
    3 : {
        'input' : [
            '|A B|  ',
            '  |C D|'
        ],
        'output':['|ABD|', '|ACD|'],
        'frags':[
            #output |ABD|
            [ {'offset':0, 'content':[1, 1   ]},
              {'offset':1, 'content':[   0, 1]} ],
            #output |ACD|
            [ {'offset':0, 'content':[1, 0,  ]},
              {'offset':1, 'content':[   1, 1]} ],
        ],
        'reverse':True,
        'evaded':{'offset':1, 'size':1}
    },
    4 : {
        'input' : [
            '|A|',
            '|B|'
        ],
        'output':['|A|', '|B|'],
        'frags':[
            #output |AB|
            [ {'offset':0, 'content':[1]},
              {'offset':0, 'content':[0]} ],
            #output |CB|
            [ {'offset':0, 'content':[0]},
              {'offset':0, 'content':[1]} ],
        ],
        'reverse':False,
        'evaded':{'offset':0, 'size':1}
    }
}
