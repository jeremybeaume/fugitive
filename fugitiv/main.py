#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import lib


def test_evasion(test_id, test_info, output, reverse):
    print
    print ("[+] " + test_info['name'] + (' - Reversed' if reverse else '')
           + ' / Output ' + test_info['output'][output])

    signature = "abcdefghijklmnopqrstuvwxyz"

    frag_evasion = lib.net.evasions.IP4MFFlagEvasion("efgh", testid=test_id,
                                                     outputid=output, reverse=reverse)

    s = lib.net.TCPsocket("eth1", "10.0.10.2", 80, evasion=frag_evasion)
    s.connect()

    payload = "GET /?data=" + signature + " HTTP/1.1\r\nHost:10.0.10.2\r\n\r\n"
    s.write(payload)

    try:
        rep = s.read()
    except IOError:
        rep = ""

    if signature in rep:
        lib.utils.raise_success("SUCCESS")
    else:
        lib.utils.raise_error("FAIL")

    s.close()


def mf_evade(x):
    test_evasion(x, lib.net.evasions.conf.mf_flag_evasion[x], 0, False)

mf_evade(2)

"""
for test_id in lib.net.evasions.conf.overlap_evasion.keys():
    test_info = lib.net.evasions.conf.overlap_evasion[test_id]

    for r in range(0, len(test_info['output'])):
        test_evasion(test_id, test_info, r, False)
        if test_info['reverse']:
            test_evasion(test_id, test_info, r, True)
"""
