#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ... import utils
from ifacelistener import PacketReceiver
import sockutils


class TCPsocket(PacketReceiver):

    SOCKET_TIMEOUT = 0.5

    INIT, SYN_SENT, SYN_RECVD, ESTABLISHED = range(4)
    _state_str = ["INIT", "SYN_SENT", "SYN_RECVD", "ESTABLISHED"]

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self, target, port,
                 evasion=None, signature=None,
                 logger=utils.testlogger.none_logger,
                 iface=None
                 ):

        self._iface = iface
        if self._iface is None:
            self._iface = sockutils.get_iface_to_target(target)

        # init the receiver on socket interface
        PacketReceiver.__init__(self, self._iface)

        self._evasion = evasion

        self._dst_ip = target
        self._dst_port = port
        self._src_ip = "0.0.0.0"
        self._src_port = 0

        self._seq = 0
        self._ack = 0

        self._state = TCPsocket.INIT
        self._synchronized = False

        self._logger = logger
        self._signature = signature

    ###### SOCKET API ######

    def connect(self):
        """
        Connect this socket
        """
        self._src_ip = sockutils.get_iface_ip4(self._iface)
        self._src_port = sockutils.get_source_port()

        self._seq = random.randint(0, 65536)
        self._ack = 0

        # SYN
        syn_pkt = self._make_pkt(flags="S")
        self._send_pkt(syn_pkt)

        # SYN_SENT state
        self._state = TCPsocket.SYN_SENT

        # Receive SYN_ACK packet
        try:
            syn_ack = self.recv_packet(timeout=TCPsocket.SOCKET_TIMEOUT)
        except:
            raise self._get_IOError("No answer from remote host {}:{}".format(
                self._dst_ip, self._dst_port))

        # Check connection RST
        if (syn_ack[TCP].flags & TCPsocket.RST):
            raise self._get_IOError("Connection RESET")
        # Check SYN ACK
        elif ((syn_ack[TCP].flags & TCPsocket.SYN) == 0
              or (syn_ack[TCP].flags & TCPsocket.ACK) == 0):
            raise self._get_IOError("Connection received not a SYN ACK packet")

        # SYN_ACK received

        # Send ACK
        self._seq += 1
        self._ack = syn_ack[TCP].seq + 1
        ack_pkt = self._make_pkt(flags="A")
        self._send_pkt(ack_pkt)

        # State ESTABLISHED
        self._state = TCPsocket.ESTABLISHED
        self._synchronized = True

    def write(self, data):
        pkt = self._make_pkt(flags="PA") / Raw(data)
        self._send_pkt(pkt)

        self._wait_ack(expected_seq=self._ack,
                       expected_ack=self._seq + len(data))
        # augment seq only if ack is received : _wait_ack raise exception when
        # error is met
        self._seq += len(data)

    def read(self, timeout=None):
        try:
            ans = self.recv_packet(timeout=TCPsocket.SOCKET_TIMEOUT)
        except IOError:
            raise self._get_IOError("Read timeout")

        if not (ans[TCP].flags & TCPsocket.PSH):
            raise self._get_IOError("Not a PSH packet")

        data = ans[Raw].load

        # send ACK packet
        self._ack += len(data)
        ack_pkt = self._make_pkt(flags="A")
        self._send_pkt(ack_pkt)

        return data

    def close(self):
        """ Try doing a FIN end, and if error or already not synchronized, send a RST """
        # send FIN_ACK packet
        if not self._synchronized and self._state != TCPsocket.INIT:
            self.reset()
            return

        fa_pkt = self._make_pkt(flags="FA")
        self._send_pkt(fa_pkt)
        self._seq += 1

        # wait for FIN_ACK answer
        remote_fa_pkt = None
        while 1:
            try:
                remote_fa_pkt = self.recv_packet(
                    timeout=TCPsocket.SOCKET_TIMEOUT)
            except IOError:
                # timeout de reception, we just leave
                self._logger.log_warning("FIN timeout with {}:{} on {}".format(
                    self._dst_ip, self._dst_port, self._iface))
                break
            if remote_fa_pkt[TCP].flags & TCPsocket.FIN:
                # break after FIN Received
                break
            # while will end : either by fin ack, or timeout
            # FIXME security : will never end if always receive ack pakets

        if remote_fa_pkt is not None:
            # recv_packet has not timed out : send final ack packet
            self._ack = remote_fa_pkt[TCP].seq + 1
            final_ack_pkt = self._make_pkt(flags="A")
            self._send_pkt(final_ack_pkt)

        # remove this socket from listening ones
        PacketReceiver.close(self)

    def reset(self):
        """ Sends a RST packet """
        pkt = Ether() / self._make_pkt(flags="RA")
        self._logger.write_pkt(pkt)
        sendp(pkt, iface=self._iface, verbose=False)

    ######################
    #### SOCKET UTILS ####
    ######################

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
            # packet.show2()
            pkt = Ether() / packet
            self._logger.write_pkt(pkt)
            sendp(pkt, iface=self._iface, verbose=False)

    def recv_packet(self, timeout=None):
        """ Receive a packet, and log it """
        pkt = PacketReceiver.recv_packet(self, timeout)
        self._logger.write_pkt(pkt)
        return pkt

    def _wait_ack(self, expected_seq, expected_ack):
        """ Wait for an ACK packet, and check synchronization """
        self._synchronized = False

        try:
            ans = self.recv_packet(timeout=TCPsocket.SOCKET_TIMEOUT)
        except IOError:
            raise self._get_IOError("Disconnected : No ACK from remote host")

        if (ans[TCP].flags & TCPsocket.RST) != 0:
            raise self._get_IOError("Disconnected : RST from remote host")

        if ans[TCP].seq != expected_seq:
            raise self._get_IOError(
                "Synchronize error : ack={} when remote host seq={}".format(self._ack, ans[TCP].seq))
        elif ans[TCP].ack != expected_ack:
            raise self._get_IOError(
                "Synchronize error : seq={} when remote host ack={}".format(self._seq, ans[TCP].ack))

        self._synchronized = True

    def _make_pkt(self, flags="A"):
        """ Create packet with current seq / ack """
        pkt = IP(src=self._src_ip, dst=self._dst_ip) \
            / TCP(sport=self._src_port, dport=self._dst_port,
                  seq=self._seq, ack=self._ack,
                  flags=flags.upper())
        return pkt

    def packet_for_me(self, pkt):
        """ Return True if packet is destined to this socket """
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            return ((pkt[IP].src == self._dst_ip)
                    and (pkt[IP].dst == self._src_ip)
                    and (pkt[TCP].sport == self._dst_port)
                    and (pkt[TCP].dport == self._src_port))
        else:
            return False

    def _get_IOError(self, msg):
        """ Create a formated Error """
        self._logger.log_error(msg)
        return IOError(msg)

    ######################
    ### EVASION UTILS  ###
    ######################

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
        p = data.find(self._signature)
        if p < 0:
            return (-1, -1)
        else:
            return (p, p + len(self._signature))
