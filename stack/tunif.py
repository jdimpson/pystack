#!/usr/bin/env python3
import fcntl
import os
import struct
import subprocess

from .utils import IFF_TUN, IFF_NO_PI, TUNSETIFF, TUNSETOWNER, hexdump

# Some constants used to ioctl the device file. I got them by a simple C
# program.
TUNSETIFF = 0x400454ca
TUNSETPERSIST = TUNSETIFF + 1
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
# see also https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_tun.h#L35

def createtundev(name="tun0", persist=False, owner=1000):

	# Open file corresponding to the TUN device.
	tun = open('/dev/net/tun', 'r+b', buffering=0)
	ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
	fcntl.ioctl(tun, TUNSETIFF, ifr)
	fcntl.ioctl(tun, TUNSETOWNER, owner)
	if persist:
		fcntl.ioctl(tun, TUNSETPERSIST, 1)
	return tun

def bringuptun(hostip,guestip,name="tun0",mtu=1500,persist=False):
	tun = createtundev(name=name,persist=persist)

	# Bring it up and assign addresses.
	if hostip == "dhcp" or hostip == "DHCP":
		print("WARNING: tun interfaces do not support DHCP (that I know of). Exiting...")
		sys.exit(1)

	#subprocess.check_call('ifconfig ' + name + ' ' + hostip + ' pointopoint ' + guestip + ' up', shell=True)
	# ip link set dev tun1 up mtu 1500
	# ip addr add dev tun1 192.168.6.1/32 peer 192.168.6.2/32
	subprocess.check_call('ip link set dev ' + name + ' up mtu ' + str(mtu), shell=True)
	if "/" not in hostip:
		hostip = "{}/32".format(hostip)
		print("assuming hostip address is {}".format(hostip))
	if "/" not in guestip:
		guestip = "{}/32".format(guestip)
		print("assuming guestip address is {}".format(guestip))
		subprocess.check_call('ip addr add dev ' + name + ' ' + hostip + ' peer ' + guestip, shell=True)
	return tun

def readtunippacket(tun,dump=False):
	l = list(os.read(tun.fileno(), 2048))
	l = bytearray(l)
	if dump:
		for x in hexdump(l):
			print(x)
	return l

def writetunippacket(tun,ippacket,dump=False):
	if dump:
		for x in hexdump(ippacket):
			print(x)
	return os.write(tun.fileno(), ippacket)

if __name__ == "__main__":
	import sys
	from signal import pause
	o=[]
	for a in sys.argv[1:]:
		print("Creating tun device {}".format(a))
		tun = createtundev(name=a)
		#tun = bringuptun('192.168.7.1', '192.168.7.2', name=a)
		o.append(tun)
	print("Pausing")
	pause()
	
