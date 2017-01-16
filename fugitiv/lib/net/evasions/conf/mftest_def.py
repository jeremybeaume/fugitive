#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

mf_flag_evasion={
    0 : {
        # defautl simple case
        'name' : 'Base case (A,B,C, C no MF)', 
        'input' : [
            '|A-MF|          ',
            '     |B-MF|     ',
            '          |C-  |'
        ],
        'output':['|ABC|'],
        'frags':[
            #output |ABC|
            [{'offset':0, 'content':[1], 'flags':'MF'},
             {'offset':1, 'content':[1], 'flags':'MF'},
             {'offset':2, 'content':[1], 'flags':'  '}]
        ],
        'evaded':{'offset':1, 'size':1}, #no real evasions
        'reverse' : True
    },

    1 : {
        # C fragment should be ignored most probably
        'name' : 'Post defrag framgent (A,B,C - B no MF)',
        'input' : [
            '|A-MF|          ',
            '     |B-  |     ',
            '          |C-MF|'
        ],
        'output':['|AB|', '|ABC'],
        'frags':[
            #output |AB|
            [{'offset':0, 'content':[1], 'flags':'MF'},
             {'offset':1, 'content':[1], 'flags':'  '},
             {'offset':2, 'content':[0], 'flags':'MF'}],
            #output |ABC|
            [{'offset':0, 'content':[1], 'flags':'MF'},
             {'offset':1, 'content':[1], 'flags':'  '},
             {'offset':2, 'content':[1], 'flags':'MF'}]
        ],
        'evaded':{'offset':2, 'size':1},
        'reverse' : False
    },

    2 : {
        # C fragment might be used, depends on MF signification
        'name': 'Middle offset-last arrived (A,C,B - B no MF)',
        'input' : [
            '|A-MF|          ',
            '          |C-MF|',
            '     |B-  |     ',
        ],
        'output':['|AB|', '|ABC|'],
        'frags':[
            #output |AB|
            [{'offset':0, 'content':[1], 'flags':'MF'},
             {'offset':2, 'content':[0], 'flags':'MF'},
             {'offset':1, 'content':[1], 'flags':'  '}],
            #output |ABC|
            [{'offset':0, 'content':[1], 'flags':'MF'},
             {'offset':2, 'content':[1], 'flags':'MF'},
             {'offset':1, 'content':[1], 'flags':'  '}]
        ],
        'evaded':{'offset':2, 'size':1},
        'reverse' : False
    },

    3 : {
        # A Fragment appears not fragmented, but ....
        'name': 'First offset not fragmented ? (B,A - A no MF)',
        'input' : [
            '     |B-MF|',
            '|A-  |     '
        ],
        'output':['|A|', '|AB|'],
        'frags':[
            #output |A|
            [{'offset':1, 'content':[0], 'flags':'MF'},
             {'offset':0, 'content':[1], 'flags':'  '}],
            #output |ABC|
            [{'offset':1, 'content':[1], 'flags':'MF'},
             {'offset':0, 'content':[1], 'flags':'  '}]
        ],
        'evaded':{'offset':1, 'size':1},
        'reverse' : False
    }
}