#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import random
from scapy.all import *

from ...utils import *

from ifacelistener import *
import utils

class TCPsocket(PacketReceiver):

    SOCKET_TIMEOUT = 3

    INIT,SYN_SENT,SYN_RECVD,ESTABLISHED = range(4)
    _state_str=["INIT","SYN_SENT","SYN_RECVD","ESTABLISHED"]

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self, iface, target, port, evasion=None):
        PacketReceiver.__init__(self, iface)
        self._iface = iface
        self._evasion = evasion;

        self._dst_ip   = target
        self._dst_port = port
        self._src_ip   = "0.0.0.0"
        self._src_port = 0

        self._seq = 0
        self._ack = 0

        self._state = TCPsocket.INIT

    def connect(self):
        """
        Connect this socket
        """
        self._src_ip   = utils.get_iface_ip4(self._iface)
        self._src_port = utils.get_source_port()

        self._seq = random.randint(0,65536)
        self._ack = 0

        ## SYN
        syn_pkt = self._make_pkt(flags="S")
        self._send_pkt(syn_pkt)

        # SYN_SENT state
        self._state = TCPsocket.SYN_SENT

        # Receive SYN_ACK packet
        syn_ack = self.recv_packet(timeout=TCPsocket.SOCKET_TIMEOUT)

        # Check connection RST
        if (syn_ack[TCP].flags & TCPsocket.RST) :
            raise self._get_IOError("Connection RESET")
        # Check SYN ACK
        elif ( (syn_ack[TCP].flags & TCPsocket.SYN) == 0
            or (syn_ack[TCP].flags & TCPsocket.ACK) == 0) :
            raise self._get_IOError("Connection received not a SYN ACK packet")
    
        # SYN_ACK received

        # Send ACK
        self._seq += 1
        self._ack = syn_ack[TCP].seq + 1
        ack_pkt = self._make_pkt(flags="A")
        self._send_pkt(ack_pkt)

        # State ESTABLISHED
        self._state = TCPsocket.ESTABLISHED

    def write(self, data):
        pkt = self._make_pkt(flags="PA") / Raw(data)
        self._send_pkt(pkt)

        self._seq += len(data)
        
        self._wait_ack()

    def read(self, timeout=None):
        try :
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

        return data;

    def close(self):
        # send FIN_ACK packet
        fa_pkt = self._make_pkt(flags="FA")
        self._send_pkt(fa_pkt)
        self._seq += 1

        #wait for FIN_ACK answer
        remote_fa_pkt = None
        while 1:
            try:
                remote_fa_pkt = self.recv_packet(timeout=TCPsocket.SOCKET_TIMEOUT)
            except IOError:
                # timeout de reception, we just leave
                raise_warning("FIN timeout with {}:{} on {}".format(self._dst_ip, self._dst_port,self._iface))
                break
            if remote_fa_pkt[TCP].flags & TCPsocket.FIN:
                # break after FIN Received
                break
            # while will end : either by fin ack, or timeout
            #FIXME security : will never end if always receive ack pakets

        if remote_fa_pkt is not None:
            # send final ack packet
            self._ack = remote_fa_pkt[TCP].seq + 1
            final_ack_pkt = self._make_pkt(flags="A")
            self._send_pkt(final_ack_pkt)

        # remove this socket from listening ones
        PacketReceiver.close(self)

    #### UTILS ####

    def _send_pkt(self, pkt):
        # evade packet
        if self._evasion is not None:
            pkt_list = self._evasion.evade(pkt)
        else:
            pkt_list = [pkt]

        # send evaded packets
        for packet in pkt_list:
            #packet.show2()
            sendp(Ether() / packet, iface=self._iface, verbose=False)

    def _wait_ack(self):
        """ Wait for an ACK packet, and check synchronization """
        try :
            ans = self.recv_packet(timeout=TCPsocket.SOCKET_TIMEOUT)
        except IOError:
            raise self._get_IOError("Disconnected : No answer from remote host")

        if (ans[TCP].flags & TCPsocket.RST ) != 0 :
            raise self._get_IOError("Disconnected : RST from remote host")

        if ans[TCP].seq != self._ack :
            raise self._get_IOError("Synchronize error : ack={} when remote host seq={}".format(self._ack, ans[TCP].seq))
        elif ans[TCP].ack != self._seq:
            raise self._get_IOError("Synchronize error : seq={} when remote host ack={}".format(self._seq, ans[TCP].ack))

        return True

    def _make_pkt(self, flags="A"):
        """ Create packet with current seq / ack """
        pkt = IP(src=self._src_ip, dst=self._dst_ip) \
            / TCP(sport=self._src_port, dport=self._dst_port,
                      seq=self._seq, ack=self._ack,
                      flags = flags.upper())
        return pkt

    def packet_for_me(self, pkt):
        """ Return True if packet is destined to this socket """
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            return ( (pkt[IP].src == self._dst_ip)
                 and (pkt[IP].dst == self._src_ip)
                 and (pkt[TCP].sport == self._dst_port)
                 and (pkt[TCP].dport == self._src_port) )
        else:
            return False

    def _get_IOError(self, msg):
        """ Create a formated Error """
        return IOError(msg + " with {}:{} on {}".format(self._dst_ip, self._dst_port,self._iface))

    def __str__(self):
        s = "TCPConn[{}/{}:{}=>{}:{},{},seq={},ack={}]".format(
            self._iface,
            self._src_ip, self._src_port,
            self._dst_ip, self._dst_port,
            _state_str[self._state],
            self._seq, self._ack,
            )



