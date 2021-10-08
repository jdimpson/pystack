#!/usr/bin/env python3
import stack.process
import stack.tunif
import stack.utils

tun = stack.tunif.bringuptun('192.168.7.1','192.168.7.2', name='tun0', persist=False)

while True:
	# Read an IP packet been sent to this TUN device.
	ippacket = stack.tunif.readtunippacket(tun, dump=True)
	o = stack.process.processIP(ippacket)
	if o is not None:
		#for x in stack.utils.hexdump(o): print(x)
		stack.tunif.writetunippacket(tun,o,dump=True)
		print("===============")
