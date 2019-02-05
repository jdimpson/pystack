#!/usr/bin/env python
import fcntl
import os
import struct
import subprocess

import utils
from utils import IFF_TUN, IFF_NO_PI, TUNSETIFF, TUNSETOWNER


# Some constants used to ioctl the device file. I got them by a simple C
# program.
TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def bringuptun(hostip,guestip,name="tun0"):

	# Open file corresponding to the TUN device.
	tun = open('/dev/net/tun', 'r+b')
	ifr = struct.pack('16sH', name, IFF_TUN | IFF_NO_PI)
	fcntl.ioctl(tun, TUNSETIFF, ifr)
	fcntl.ioctl(tun, TUNSETOWNER, 1000)

	# Bring it up and assign addresses.
	if hostip == "dhcp" or hostip == "DHCP":
		print "WARNING: tun interfaces do not support DHCP (that I know of). Exiting..."
		sys.exit(1)
	subprocess.check_call('ifconfig ' + name + ' ' + hostip + ' pointopoint ' + guestip + ' up', shell=True)

	return tun

def readtunippacket(tun,dump=False):
	l = list(os.read(tun.fileno(), 2048))
	if dump:
		for x in utils.hexdump(l):
			print x
	return bytearray(l)

def writetunippacket(tun,ippacket,dump=False):
	if dump:
		for x in utils.hexdump(ippacket):
			print x
	return os.write(tun.fileno(), ''.join(ippacket))


