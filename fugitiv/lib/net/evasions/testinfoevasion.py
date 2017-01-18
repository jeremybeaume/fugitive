#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import baseevasion

class TestInfoBasedEvasion:
    def __init__(self, test_info_dict, testid, outputid, reverse):
        self._testid = testid
        self._outputid = outputid
        self._reverse = reverse

        self._test_info = test_info_dict[testid]

    def get_name(self):
        return (str(self._testid) + " - " + self._test_info['name'] + (' - Reversed' if self._reverse else '')
                    + ' / Output ' + self._test_info['output'][self._outputid])

    @staticmethod
    def get_all_tests(test_info_dict):
        test_list=[]
        for test_id in test_info_dict.keys():
            test_info = test_info_dict[test_id]

            for outputid in range(0, len(test_info['output'])):
                test_list.append((test_id, outputid, False))
                if test_info['reverse']:
                    test_list.append((test_id, outputid, True))
        return test_list