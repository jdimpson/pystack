#!/usr/bin/env python3
import fcntl
import atexit
import socket

# see https://man7.org/linux/man-pages/man7/netdevice.7.html
#ioctl(5, SIOCGIFFLAGS, {ifr_name="eth0", ifr_flags=IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST}) = 0
#ioctl(5, SIOCGIFHWADDR, {ifr_name="eth0", ifr_hwaddr={sa_family=ARPHRD_ETHER, sa_data=dc:a6:32:36:c4:a1}}) = 0
#ioctl(5, SIOCGIFMTU, {ifr_name="eth0", ifr_mtu=1500}) = 0
#ioctl(5, SIOCGIFMAP, {ifr_name="eth0", ifr_map={mem_start=0, mem_end=0, base_addr=0, irq=0, dma=0, port=0}}) = 0
#ioctl(5, SIOCGIFTXQLEN, {ifr_name="eth0", ifr_qlen=1000}) = 0

def bringupraw(iface="eth0",promisc=True):
	# NOTE: highly Linux specific
	import ctypes,fcntl
	class ifreq(ctypes.Structure):
		_fields_ = [	("ifr_ifrn",  ctypes.c_char * 16),
				("ifr_flags", ctypes.c_short)]
	ETH_P_ALL = 3
	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	s.bind((iface,ETH_P_ALL))
	#s.setblocking(0)
	if promisc:
		IFF_PROMISC = 0x100	# maybe even archicture and kernel specific
		SIOCGIFFLAGS = 0x8913
		SIOCSIFFLAGS = 0x8914
		ifr=ifreq()
		ifr.ifr_ifrn=iface.encode('utf-8')
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
			print(x)
	return bytearray(l)

def writerawethframe(sock, macaddr=None, vlan=None):
	raise RuntimeError("writerawethframe() not implemented yet")
