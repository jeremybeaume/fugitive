#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

from scapy import *
#from ../baseevasion import *


"""
** General Information for IPv4 information test **

Dict of IPv4 fragmentation tests :
base : dict(test_id=>test_infos)

test_infos = dict :
    'input'  : array of string, to be printed vertically, in the list order
               displays the form of the packets sent
    'output' : array of string, corresponding to possible outputs defragmentation
    'frags'  : array of fragements array to be sent, for each output,
               to get correct defragmentation for the considered output,
               and junk for the others output
    'reverse': Do the test with fragment sent in other order

fragment : dict :
    'offset' : offset from the begining of signature area
               (one fragment must at least have offset = 0)
    'form'   : array of int for content
               0 means take content of the input packet
               1 means generate junk for this part
"""


"""
Specific Infos for overlap_test :

The overlap test breaks the packet around the signature :
DATA | SIGNATURE | DATA

So there is one fragment with begining test data
it uses the test information to make overlaping fragment around signature
the last fragment is dinal data.

IE : the test :
|A|junk|
  |  B |C|

Gives the fragments :
|DATA|
     |A|junk|
       |  B |C|
              |DATA|
"""
overlap_test={
    0 : {
        'input' : [
            '|A B|',
            '|C|  '
        ],
        'output':['|AB|', '|CB|'],
        'frags':[
            #output |AB|
            [ {'offset':0, 'form':[1, 1]},
              {'offset':0, 'form':[0   ]} ],
            #output |CB|
            [ {'offset':0, 'form':[0, 1]},
              {'offset':0, 'form':[1   ]} ]
        ],
        'reverse':True
    },
    1 : {
       'input' : [
            '|A B C|',
            '  |D|  '
        ]
        'output':['|ABC|', '|ADC|'],
        'frags':[
            #output |ABC|
            [ {'offset':0, 'form':[1, 1, 1]},
              {'offset':1, 'form':[   0   ]} ],
            #output |ADC|
            [ {'offset':0, 'form':[1, 0, 1]},
              {'offset':1, 'form':[   1   ]} ]
        ],
        'reverse':True
    },
    2 : {
        'input' : [
            '|A B|',
            '  |C|'
        ]
        'output':['|AB|', '|AC|'],
        'frags':[
            #output |AB|
            [ {'offset':0, 'form':[1, 1]},
              {'offset':1, 'form':[   0]} ],
            #output |AC|
            [ {'offset':0, 'form':[1, 0]},
              {'offset':1, 'form':[   1]} ],
        ],
        'reverse':True
    },
    3 : {
        'input' : [
            '|A B|  ',
            '  |C D|'
        ]
        'output':['|ABD|', '|ACD|'],
        'frags':[
            #output |ABD|
            [ {'offset':0, 'form':[1, 1   ]},
              {'offset':1, 'form':[   0, 1]} ],
            #output |ACD|
            [ {'offset':0, 'form':[1, 0,  ]},
              {'offset':1, 'form':[   1, 1]} ],
        ],
        'reverse':True
    },
    4 : {
        'input' : [
            '|A B|',
            '|C D|'
        ]
        'output':['|AB|', '|CD|'],
        'frags':[
            #output |AB|
            [ {'offset':0, 'form':[1, 1]},
              {'offset':0, 'form':[0, 0]} ],
            #output |CB|
            [ {'offset':0, 'form':[0, 0]},
              {'offset':0, 'form':[1 ,1]} ],
        ],
        'reverse':False
    }
}
