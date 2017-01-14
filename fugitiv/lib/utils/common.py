#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import sys,time

class colors:
    DEFAULT   = '\033[0m'
    BOLD      = '\033[1m'
    ITALIC    = '\033[3m'
    UNDERLINE = '\033[4m'

    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'

def raise_success(msg):
    print colors.GREEN + str(msg) + colors.DEFAULT;
    sys.stdout.flush()
    
def raise_info(msg, verbose=1):
    print colors.DEFAULT + str(msg) + colors.DEFAULT;
    sys.stdout.flush()

def raise_warning(msg):
    print colors.YELLOW + str(msg) + colors.DEFAULT;
    sys.stdout.flush()

def raise_error(msg):
    print colors.RED + str(msg) + colors.DEFAULT;
    sys.stdout.flush()

def exit(code=1):
    sys.exit(code)

def sleep(n):
    time.sleep(n)
