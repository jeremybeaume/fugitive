#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ... import utils
from ifacelistener import PacketReceiver
import sockutils


class TCPstates:

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


class BaseTCP4Socket(PacketReceiver):

    SOCKET_TIMEOUT = 0.5

    def __init__(self, target_config, port, iface=None,
                 logger=utils.testlogger.none_logger,
                 ip_dst=None, ip_src=None, port_src=None
                 ):
        """
        iface, ip_dst, ip_src and port_src overwrite default scapy values
        """

        self.target_config = target_config

        self.iface = iface
        if self.iface is None:
            self.iface = sockutils.get_iface_to_target(target_config["ipv4"])

        # init the receiver on socket interface
        PacketReceiver.__init__(self, self.iface)

        self.dst_ip = target_config["ipv4"]
        self.dst_port = port
        self.src_ip = ip_src
        self.src_port = port_src

        if self.src_ip is None:
            self.src_ip = sockutils.get_iface_ip4(self.iface)

        self._src_broadcast = sockutils.get_iface_ip4_broadcast(self.iface)

        if self.src_port is None:
            self.src_port = sockutils.get_source_port()

        self._seq = random.randint(0, 65536)
        self._ack = 0

        self._state = TCPstates.INIT
        self._synchronized = False

        self._logger = logger

    ###### SOCKET API ######

    def connect(self):
        """
        Connect this socket
        """

        # SYN
        syn_pkt = self.make_pkt(flags="S")
        self._send_pkt(syn_pkt)

        # SYN_SENT state
        self._state = TCPstates.SYN_SENT

        # Receive SYN_ACK packet
        try:
            syn_ack = self.recv_packet()
        except:
            raise self._get_IOError("No answer from remote host {}:{}".format(
                self.dst_ip, self.dst_port))

        # Check connection RST
        if (syn_ack[TCP].flags & TCPstates.RST):
            raise self._get_IOError("Connection RESET")
        # Check SYN ACK
        elif ((syn_ack[TCP].flags & TCPstates.SYN) == 0
              or (syn_ack[TCP].flags & TCPstates.ACK) == 0):
            raise self._get_IOError("Connection received not a SYN ACK packet")

        # SYN_ACK received

        # Send ACK
        self._seq += 1
        self._ack = syn_ack[TCP].seq + 1
        ack_pkt = self.make_pkt(flags="A")
        self._send_pkt(ack_pkt)

        # State ESTABLISHED
        self._state = TCPstates.ESTABLISHED
        self._synchronized = True

    def write(self, data):
        pkt = self.make_pkt(flags="PA") / Raw(data)
        self._send_pkt(pkt)

        self._wait_ack(expected_seq=self._ack,
                       expected_ack=self._seq + len(data))
        # augment seq only if ack is received : _wait_ack raise exception when
        # error is met
        self._seq += len(data)

    def read(self, timeout=None):
        try:
            ans = self.recv_packet()
        except IOError:
            raise self._get_IOError("Read timeout")

        if not (ans[TCP].flags & TCPstates.PSH):
            raise self._get_IOError("Not a PSH packet")

        data = ans[Raw].load

        # send ACK packet
        self._ack += len(data)
        ack_pkt = self.make_pkt(flags="A")
        self._send_pkt(ack_pkt)

        return data

    def close(self):
        """ Try doing a FIN end, and if error or already not synchronized, send a RST """
        # send FIN_ACK packet
        if not self._synchronized and self._state != TCPstates.INIT:
            self.reset()
            return

        fa_pkt = self.make_pkt(flags="FA")
        self._send_pkt(fa_pkt)
        self._seq += 1

        # wait for FIN_ACK answer
        remote_fa_pkt = None
        while 1:
            try:
                remote_fa_pkt = self.recv_packet()
            except IOError:
                # timeout de reception, we just leave
                self._logger.log_warning("FIN timeout with {}:{} on {}".format(
                    self.dst_ip, self.dst_port, self.iface))
                break
            if remote_fa_pkt[TCP].flags & TCPstates.FIN:
                # break after FIN Received
                break
            # while will end : either by fin ack, or timeout
            # FIXME security : will never end if always receive ack pakets

        if remote_fa_pkt is not None:
            # recv_packet has not timed out : send final ack packet
            self._ack = remote_fa_pkt[TCP].seq + 1
            final_ack_pkt = self.make_pkt(flags="A")
            self._send_pkt(final_ack_pkt)

        # remove this socket from listening ones
        PacketReceiver.close(self)

    def reset(self):
        """ Sends a RST packet directly (no evasions) """
        pkt = Ether() / self.make_pkt(flags="RA")
        self._logger.write_pkt(pkt)
        #sendp(pkt, iface=self.iface, verbose=False)

    ######################
    #### SOCKET UTILS ####
    ######################

    def _send_pkt(self, pkt):
        """ Sends a packet and log it """
        pkt = Ether() / pkt
        self._logger.write_pkt(pkt)
        sendp(pkt, iface=self.iface, verbose=False)

    def recv_packet(self):
        """ Receive a packet, and log it """
        pkt = PacketReceiver.recv_packet(
            self, timeout=BaseTCP4Socket.SOCKET_TIMEOUT)
        self._logger.write_pkt(pkt)
        return pkt

    def _wait_ack(self, expected_seq, expected_ack):
        """ Wait for an ACK packet, and check synchronization """
        self._synchronized = False
        cont = True
        while cont:
            cont = False
            try:
                ans = self.recv_packet()
            except IOError:
                raise self._get_IOError(
                    "Disconnected : No correct ACK from remote host")

            if (ans[TCP].flags & TCPstates.RST) != 0:
                raise self._get_IOError("Disconnected : RST from remote host")

            if ans[TCP].seq != expected_seq:
                raise self._get_IOError(
                    "Synchronize error : expected seq={} when remote host seq={}".format(expected_seq, ans[TCP].seq))
            elif ans[TCP].ack != expected_ack:
                cont = True  # wait for ACK of all the sent data

        self._synchronized = True

    def make_pkt(self, flags="A"):
        """ Create packet with current seq / ack """
        pkt = IP(src=self.src_ip, dst=self.dst_ip) \
            / TCP(sport=self.src_port, dport=self.dst_port,
                  seq=self._seq, ack=self._ack,
                  flags=flags.upper())
        return pkt

    def packet_for_me(self, pkt):
        """ Return True if packet is destined to this socket, implements PacketReceiver"""
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            return ((pkt[IP].src == self.dst_ip)
                    and (pkt[IP].dst == self.src_ip or pkt[IP].dst == self._src_broadcast)
                    and (pkt[TCP].sport == self.dst_port)
                    and (pkt[TCP].dport == self.src_port))
        else:
            return False

    def _get_IOError(self, msg):
        """ Create a formated Error """
        self._logger.log_error(msg)
        return IOError(msg)
