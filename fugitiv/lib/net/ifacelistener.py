#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Written by : Jeremy BEAUME

import scapy.all as scapy 
import Queue
import threading
from .. import utils

_iface_sniffers={}

def _get_listener(iface):
	""" Get the listener for an interface """
	if iface in _iface_sniffers:
		return _iface_sniffers[iface]
	else:
		l = _IfaceSniffer(iface)
		_iface_sniffers[iface] = l
		l.start() #always sniff the interfaces
		return l

class PacketReceiver:
	""" Receiver of packets """

	def __init__(self, iface):
		self._sniffer = _get_listener(iface)
		self._pkt_queue = Queue.Queue()
		self._sniffer.add_receiver(self)

	def recv_packet(self, timeout=None):
		""" receive a packet during the timeout, returns None if no packet received """
		try:
			return self._pkt_queue.get(block=True, timeout=timeout)
		except Queue.Empty:
			return None

	def packet_for_me(self, pkt):
		"""
		To be implemented is inherited classes
		return true is this packet is to be received
		"""
		pass

	def _give_packet(self, pkt):
		""" Adds a packet for this receiver """
		if self.packet_for_me(pkt):
			try:
				self._pkt_queue.put(pkt, block=False)
			except Queue.Full:
				# Drop packet
				utils.raise_warning("Packet dropped : queue is full")

	def close(self):
		""" Closes this receiver ( will not receive packet anymore) """
		self._sniffer.remove_receiver(self)


class _IfaceSniffer:
	"""
	Private class, listening to an interface
	Should not ne intanciate as is : use get_listener
	"""

	def __init__(self, iface):
		self._iface = iface
		self._started = False

	def start(self):
		""" Start a new thread to sniff the interface """
		if not self._started:
			self._started = True
			self._receivers = []
			t = threading.Thread(target=_IfaceSniffer_thread, args=(self,))
			t.setDaemon(True)
			t.start()

	def add_receiver(self, receiver):
		self._receivers.append(receiver)

	def remove_receiver(self, receiver):
		self._receivers.remove(receiver)

	def handle_packet(self, pkt):
		utils.raise_info("Packet on " + self._iface)


def _IfaceSniffer_thread(sniffer):
	utils.raise_info("Start sniffing on "+ sniffer._iface)
	scapy.sniff(iface=sniffer._iface, prn=lambda pkt: sniffer.handle_packet(pkt))

