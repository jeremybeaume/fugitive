#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

import json


def load_config_file(path):
    with open(path, "r") as file:
        config = json.load(file)
    return config
