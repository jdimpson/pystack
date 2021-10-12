#!/usr/bin/env python3
import stack.process
import stack.tunif
import stack.utils

hostip  = '192.168.7.1'
guestip = '192.168.7.2'
tun = stack.tunif.bringuptun(hostip, guestip, name='tun0', persist=False)
pe = stack.process.packetEngine(myipv4addr = guestip)

while True:
	# Read an IP packet been sent to this TUN device.
	ippacket = stack.tunif.readtunippacket(tun, dump=True)
	try:
		i,o = pe.processIP(ippacket)
		for l in i: print(l)
		print("")
		if o is not None:
			#for x in stack.utils.hexdump(o): print(x)
			print("RESPONSE\n===============")
			stack.tunif.writetunippacket(tun,o,dump=True)
			print("")
	except stack.process.IgnorePacket as e:
		pass
	except BrokenPipeError as e:
		exit(0)
