#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

from .. import net
from .. import utils


def test_http_evasion(evasion):
    signature = "abcdefghijklmnopqrstuvwxyz"
    payload = "GET /?data=" + signature + "   HTTP/1.1\r\nHost:10.0.10.2\r\n\r\n"

    evasion.set_signature(signature)

    utils.print_item(evasion.get_name())

    s = net.TCPsocket("eth1", "10.0.10.2", 80, evasion=evasion)
    s.connect()

    try:
        s.write(payload)
        rep = s.read()

        # print rep
        if "SUCCESS" in rep:
            utils.print_success("SUCCESS")
        else:
            utils.print_error("FAIL") #\n" + rep)

    except IOError as e:
        utils.print_error("FAIL : " + str(e))

    s.close()
