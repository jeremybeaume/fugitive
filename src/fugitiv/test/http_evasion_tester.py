#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: Jérémy BEAUME

from .. import net
from .. import utils

signature = "abcdefghijklmnopqrstuvwxyz"


def attack_payload(target):
    return ("GET /?data=" + signature + "   HTTP/1.1\r\n"
            + "Host:" + target + "\r\n\r\n")


def check_test(target, port):

    check_payload = "GET /?data=check HTTP/1.1\r\nHost:" + target + "\r\n\r\n"

    interface = net.socket.sockutils.get_iface_to_target(target)

    print "[?] Check connection"
    print "Output interface for {} is {}".format(target, interface)
    s = net.TCPsocket(target, port, evasion=None)
    try:
        s.connect()
        s.write(check_payload)
        s.close()
        utils.print_success("CONNECTION OK")
    except IOError as e:
        utils.print_error(str(e))
        utils.print_error(
            "You may want to run : iptables -A OUTPUT -p tcp --tcp-flags RST RST -o {} -j DROP".format(interface))
        return False

    print "[?] Check detection"
    s = net.TCPsocket(target, 80, evasion=None)
    try:
        s.connect()
        s.write(attack_payload(target))
        s.close()
        utils.print_error("DETECTION FAILED")
        return False
    except IOError as e:
        utils.print_success("DETECTION OK : " + str(e))

    return True


def test(target, port, evasion, testlogger):

    if evasion is not None:
        evasion.signature = signature

    ret = (True,)

    s = net.TCPsocket(target=target, port=port,
                      evasion=evasion,
                      logger=testlogger)

    try:
        s.connect()
        payload = attack_payload(target)
        testlogger.println("Writing payload :\n{}\n".format(payload),
                           verbose=5)
        s.write(payload)
        rep = s.read()
        testlogger.println("Answer from server :\n{}\n".format(rep), verbose=5)

        # print rep
        if "SUCCESS" in rep:
            ret = (True, '')
        else:
            ret = (False, "Bad response from server")

    except IOError as e:
        ret = (False, str(e))

    s.close()

    return ret
