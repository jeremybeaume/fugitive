#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME


def get_all_tests(test_def_dict):
    """
    Get all possible evasion parameters for a test_def_dict
    returns a list[(testid, outputid, reverse, type)]
    """
    test_list = []
    for test_id in test_def_dict.keys():
        test_info = test_def_dict[test_id]

        # get all tests for the test_info
        type_l = test_info.get('type', [])
        if len(type_l) == 0:
            raise ValueError(
                "Parsing evasion test definition : 'type' is not defined or empty ")

        for evasion_type in type_l:
            for outputid in range(0, len(test_info['output'])):
                test_list.append((test_id, outputid, False, evasion_type))
                if test_info['reverse']:
                    test_list.append(
                        (test_id, outputid, True, evasion_type))
    return test_list
