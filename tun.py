#!/usr/bin/env python3
import stack.process
import stack.tunif
import stack.utils

tun = stack.tunif.bringuptun('192.168.7.1','192.168.7.2', name='tun0', persist=False)

while True:
	# Read an IP packet been sent to this TUN device.
	ippacket = stack.tunif.readtunippacket(tun, dump=True)
	i,o = stack.process.processIP(ippacket)
	for l in i:
		print(l)
	print("")
	for p in o:
		#for x in stack.utils.hexdump(p): print(x)
		print("RESPONSE\n===============")
		stack.tunif.writetunippacket(tun,p,dump=True)
		print("")
