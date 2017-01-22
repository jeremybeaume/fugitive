#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import baseevasion


class TestInfoBasedEvasion(baseevasion.BaseEvasion):
    """
    Evasion using a test information dict
    """

    def __init__(self, layer, test_info_dict, testid, outputid, reverse, signature=None):

        self._testid = testid
        self._outputid = outputid
        self._reverse = reverse

        self._test_info = test_info_dict[testid]

        name = (str(self._testid) + " - " + self._test_info['name'] + (' - Reversed' if self._reverse else '')
                + ' / Output ' + self._test_info['output'][self._outputid])
        evasionid = (str(testid) + "." + str(outputid) +
                     "." + str(int(reverse)))

        baseevasion.BaseEvasion.__init__(
            self, name=name, evasionid=evasionid, layer=layer, signature=signature)

    @staticmethod
    def get_all_tests(test_info_dict):
        test_list = []
        for test_id in test_info_dict.keys():
            test_info = test_info_dict[test_id]

            for outputid in range(0, len(test_info['output'])):
                test_list.append((test_id, outputid, False))
                if test_info['reverse']:
                    test_list.append((test_id, outputid, True))
        return test_list

    @staticmethod
    def generate_evasion_list(test_info_dict, class_object):
        evasion_list = class_object.evasion_list

        input_list = TestInfoBasedEvasion.get_all_tests(test_info_dict)
        for t in input_list:
            evasion_list.append(class_object(testid=t[0], outputid=t[1],
                                             reverse=t[2], signature=None))
