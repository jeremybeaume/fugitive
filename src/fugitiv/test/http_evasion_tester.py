#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

from .. import net
from .. import utils

interface = "eth2"
target = "10.0.12.2"

check_payload = "GET /?data=check HTTP/1.1\r\nHost:" + target + "\r\n\r\n"

signature = "abcdefghijklmnopqrstuvwxyz"
attack_payload = ("GET /?data=" + signature + "   HTTP/1.1\r\n"
                  + "Host:" + target + "\r\n\r\n")


def check_test():

    print "[?] Check connection"
    s = net.TCPsocket(interface, target, 80, evasion=None)
    try:
        s.connect()
        s.write(check_payload)
        s.close()
        utils.print_success("CONNECTION OK")
    except IOError as e:
        utils.print_error(str(e))
        return False

    print "[?] Check detection"
    s = net.TCPsocket(interface, target, 80, evasion=None)
    try:
        s.connect()
        s.write(attack_payload)
        s.close()
        utils.print_error("DETECTION FAILED")
        return False
    except IOError as e:
        utils.print_success("DETECTION OK : " + str(e))

    return True


def test(evasion, testlogger):

    if evasion is not None:
        evasion.signature = signature

    ret = (True,)

    s = net.TCPsocket(iface=interface,
                      target=target, port=80,
                      evasion=evasion,
                      logger=testlogger)

    try:
        s.connect()

        s.write(attack_payload)
        rep = s.read()

        # print rep
        if "SUCCESS" in rep:
            ret = (True, '')
        else:
            ret = (False, "Bad response from server")

    except IOError as e:
        ret = (False, str(e))

    s.close()

    return ret
