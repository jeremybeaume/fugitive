#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

from ... import utils
from basetcpsocket import BaseTCP4Socket


class EvasionTCP4Socket(BaseTCP4Socket):
    """
    Socket able to evade some signature using evasions
    """

    def __init__(self, target_config, port, iface=None,
                 logger=utils.testlogger.none_logger,
                 ip_dst=None, ip_src=None, port_src=None,
                 evasion=None, signature=None):

        BaseTCP4Socket.__init__(self, target_config=target_config,
                                port=port, iface=iface, logger=logger)

        self._evasion = evasion
        self._signature = signature

    def _send_pkt(self, pkt):
        """ Sends a packet, and apply evasion if not None """
        # evade packet
        if self._evasion is not None:
            (sign_begin, sign_size) = self._find_signature(pkt)
            # returns (-1,-1) if self._signature is none
            if sign_size > 0:  # if signature matched

                if self._evasion.get_type() == 'bypass':
                    # give the packet to bypass
                    pkt_list = self._evasion.evade_signature(pkt, sign_begin=sign_begin,
                                                             sign_size=sign_size, logger=self._logger)
                elif self._evasion.get_type() == 'inject':
                    # gives a TCP RST to inject, and adds the true payload
                    # packet after
                    self._logger.println("Injecting TCP RST", verbose=1)
                    evaded_rst_frags = self._evasion.evade_signature(self._make_pkt(flags="RA"),
                                                                     sign_begin=-1, sign_size=-1,
                                                                     logger=self._logger)
                    # adds the payload packet after
                    pkt_list = evaded_rst_frags + [pkt]
                else:
                    raise ValueError("Unrecognized evasion type \"{}\"".format(
                        self._evasion.get_type()))
            else:
                pkt_list = [pkt]
        else:
            pkt_list = [pkt]

        # send evaded packets
        for packet in pkt_list:
            BaseTCP4Socket._send_pkt(self, packet)

    def _find_signature(self, pkt):
        """
        Search the signature in the layer payload content
        return (begin, size) of the matched content, (-1,-1) if not found
        """

        if self._signature is None:
            return (-1, -1)

        # Check layer and get layer payload
        layer = self._evasion.get_layer()
        if layer is not None:
            if pkt.haslayer(layer):
                data = str(pkt[layer].payload)
            else:
                return (-1, -1)  # the pakcet has not the interrested layer
        else:
            data = str(pkt)

        # search the signature
        p = data.find(str(self._signature))
        if p < 0:
            return (-1, -1)
        else:
            return (p, p + len(self._signature))
