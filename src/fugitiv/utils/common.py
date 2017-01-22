#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys
import time
import string
import math
import pprint

pp = pprint.PrettyPrinter(indent=4)


class colors:
    DEFAULT = '\033[0m'
    BOLD = '\033[1m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'


def print_success(msg):
    print colors.GREEN + str(msg) + colors.DEFAULT
    sys.stdout.flush()


def print_info(msg, verbose=1):
    print colors.DEFAULT + str(msg) + colors.DEFAULT
    sys.stdout.flush()


def print_warning(msg):
    print colors.YELLOW + str(msg) + colors.DEFAULT
    sys.stdout.flush()


def print_error(msg):
    print colors.RED + str(msg) + colors.DEFAULT
    sys.stdout.flush()


def print_notice(msg):
    print colors.CYAN + str(msg) + colors.DEFAULT
    sys.stdout.flush()


def print_title(msg):
    print colors.CYAN + colors.BOLD + "== " + msg + " ==" + colors.DEFAULT


def print_item(msg):
    print colors.BLUE + "[+] " + msg + colors.DEFAULT


def exit(code=1):
    sys.exit(code)


def sleep(n):
    time.sleep(n)


def get_non_ascii_string(mystring):
    res = ""
    for c in mystring:
        if c in string.ascii_letters or c in string.digits or c in '*!?_-+=/\[]{}%$#@&':
            res += c
        else:
            res += "."
    return res


def get_flags_str(value, flags, spaces=False):
    """
    flags = string
    adds flags[i] if (value & 2^i)
    add spaces else if spaces is True
    """
    if flags is None or value is None:
        return ''
    s = ""
    mask = 1
    for i in range(0, len(flags)):
        if value & mask:
            s += flags[i]
        else:
            if spaces:
                s += " "
        mask *= 2
    return s
