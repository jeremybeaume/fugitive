#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Fugitive : Network evasion tester
# Copyright (C) 2017 Jérémy BEAUME (jeremy [dot] beaume (a) protonmail [dot] com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import errno

from .. import net
from .. import utils

name="http_tester"

def _attack_payload(target_config, tester_config):
    return ("GET " + tester_config["url"] + " HTTP/1.1\r\n"
            + "Host:" + target_config["http_host"] + "\r\n\r\n")


def check_test(target_config, tester_config):

    target = target_config["ipv4"]
    port = target_config["http_port"]

    interface = net.socket.sockutils.get_iface_to_target(target)

    print "[?] Check connection"
    print "Output interface for {} is {}".format(target, interface)
    s = net.EvasionTCP4Socket(target_config=target_config, port=port)
    try:
        s.connect()
        # send dumb data and check there is an answer
        s.write('check connection')
        s.close()
        utils.print_success("CONNECTION OK")
    except IOError as e:
        utils.print_error(str(e))
        if e[0] == errno.EPERM:
            utils.print_error("You neede to be root to send crafted packets !")
        else:
            utils.print_error(
                "You may want to run : \n"
                "iptables -A OUTPUT -p tcp --tcp-flags RST RST -o {} -j DROP"
                .format(interface))
        return False

    print "[?] Check detection"
    s = net.EvasionTCP4Socket(target_config=target_config, port=80)
    try:
        s.connect(data=_attack_payload(target_config, tester_config))
        rep = s.read()
        s.close()
        if "SUCCESS" in rep:
            utils.print_error("Test succeed : DETECTION FAILED")
        else:
            utils.print_error("Answer is not correct :")
            print rep
        return False
    except IOError as e:
        utils.print_success("DETECTION OK : " + str(e))

    return True


def test(target_config, tester_config, evasion, testlogger):
    ret = (True,)

    s = net.EvasionTCP4Socket(target_config=target_config,
                              port=target_config["http_port"],
                              evasion=evasion,
                              signature=tester_config["signature"],
                              logger=testlogger)

    try:
        payload = _attack_payload(target_config, tester_config)
        testlogger.println("Connecting with stored payload :\n{}\n".format(payload),
                           verbose=2)

        s.connect(data=payload)
        rep = s.read()
        testlogger.println("Answer from server :\n{}\n".format(rep), verbose=2)

        # print rep
        if tester_config["success"] in rep:
            ret = (True, '')
        else:
            ret = (False, "Bad response from server")

    except IOError as e:
        ret = (False, str(e))

    s.close()

    return ret
