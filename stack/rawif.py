#!/usr/bin/env python
import fcntl
import atexit
import socket

def bringupraw(iface="eth0"):
	# NOTE: highly Linux specific
	import ctypes,fcntl
	class ifreq(ctypes.Structure):
		_fields_ = [	("ifr_ifrn",  ctypes.c_char * 16),
				("ifr_flags", ctypes.c_short)]
	ETH_P_ALL = 3
	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	s.bind((iface,ETH_P_ALL))
	#s.setblocking(0)
	IFF_PROMISC = 0x100	# maybe even archicture and kernel specific
	SIOCGIFFLAGS = 0x8913
	SIOCSIFFLAGS = 0x8914
	ifr=ifreq()
	ifr.ifr_ifrn=iface
	fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, ifr)
	ifr.ifr_flags |= IFF_PROMISC
	fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)
	def depromisc():
		ifr.ifr_flags &= ~IFF_PROMISC
		fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)
	atexit.register(depromisc)
	return s

def readrawethframe(sock,dump=False):
	import string
	l = list(sock.recv(2048))
	if dump:
		for x in hexdump(l):
			print x
	return bytearray(l)

def writerawethframe(sock):
	raise RuntimeError("writerawethframe() not implemented yet")
