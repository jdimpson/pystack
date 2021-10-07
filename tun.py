#!/usr/bin/env python3
import stack.process
import stack.tunif

tun = stack.tunif.bringuptun('192.168.7.1','192.168.7.2', name='tun0')

while True:
	# Read an IP packet been sent to this TUN device.
	ippacket = stack.tunif.readtunippacket(tun, dump=True)
	#o = stack.process.processIP(ippacket)
	#if o is not None:
	#	stack.tunif.writetunippacket(tun,o,dump=True)
