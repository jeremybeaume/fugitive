#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

evasion_tree = {}
"""
NODE = dict{name:(NODE|evasion)}
"""


def _list_evasion_modules():
    """
    Imports all submodules, amd list the evasions modules
    """
    global evasion_list

    import pkgutil
    import os
    import sys
    import importlib
    import inspect
    import baseevasion

    evasion_mother_class = baseevasion.BaseEvasion

    def search_for_evasions_class(module):
        # print "searching :", module
        clsmembers = inspect.getmembers(sys.modules[module],
                                        lambda x: inspect.isclass(x) and x.__module__ == module)
        for class_member in clsmembers:
            class_obj = class_member[1]
            if (class_obj != evasion_mother_class
                    and issubclass(class_obj, evasion_mother_class)):
                evasion_folder = getattr(class_obj, "evasion_folder", None)
                evasion_list = getattr(class_obj, "evasion_list", None)
                if evasion_list is not None and evasion_folder is not None:
                    l = evasion_tree.get(evasion_folder, [])
                    l += evasion_list
                    folder_list = evasion_folder.split('/')
                    cur_dict = evasion_tree
                    for f in folder_list:
                        if f not in cur_dict:
                            cur_dict[f] = {}
                        cur_dict = cur_dict[f]
                    for ev in evasion_list:
                        cur_dict[ev.get_id()] = ev

    def import_submodules_rec(path, name):
        for _loader, _modulename, _is_pkg in pkgutil.iter_modules(path=[path]):
            full_name = name + "." + _modulename
            importlib.import_module(full_name)
            if _is_pkg:
                import_submodules_rec(path + "/" + _modulename, name=full_name)
            else:
                search_for_evasions_class(full_name)

    import_submodules_rec(sys.modules[__name__].__path__[0], __name__)

_list_evasion_modules()
del(_list_evasion_modules)
