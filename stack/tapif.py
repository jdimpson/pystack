#!/usr/bin/env python
import fcntl
import os
import struct
import subprocess
import atexit
import socket

import utils
from utils import IFF_TAP, IFF_NO_PI, TUNSETIFF, TUNSETOWNER

def bringuptap(hostip,guestip,name="tap0"):

	# Open file corresponding to the TAP device.
	tun = open('/dev/net/tun', 'r+b')
	ifr = struct.pack('16sH', name, IFF_TAP | IFF_NO_PI)
	fcntl.ioctl(tun, TUNSETIFF, ifr)
	fcntl.ioctl(tun, TUNSETOWNER, 1000)

	# Bring it up and assign addresses.
	if hostip == "dhcp" or hostip == "DHCP":
		subprocess.check_call('ifconfig ' + name + ' up', shell=True)
		# Need better control of this process
		utils.dhproc = subprocess.Popen('/sbin/dhclient ' + name, shell=True)
		atexit.register(utils.stop_dhclient)
	else:
		subprocess.check_call('ifconfig ' + name + ' ' + hostip + ' pointopoint ' + guestip + ' up', shell=True)

	return tun

def readtapethframe(tap,dump=False):
	l = list(os.read(tap.fileno(), 2048))
	if dump:
		for x in hexdump(l):
			print x
	return bytearray(l)

def writetapethframe(tap):
	raise RuntimeError("writetapethframe() not implemented yet")
