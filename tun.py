#!/usr/bin/env python3
import sys

import stack.process
import stack.tunif
import stack.utils

class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def writelines(self, datas):
       self.stream.writelines(datas)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)
sys.stdout = Unbuffered(sys.stdout)

hostip  = '192.168.8.1'
guestip = '192.168.8.2'
tun = stack.tunif.bringuptun(hostip, guestip, name='tun0', persist=False)
pe = stack.process.packetEngine(myipv4addr = guestip)

while True:
	# Read an IP packet been sent to this TUN device.
	ippacket = stack.tunif.readtunippacket(tun, dump=False)
	try:
		# tun interfaces don't do ethernet frames
		i,o = pe.processIP(ippacket)
		for l in i: print(l)
		print("")
		if o is not None:
			print("RESPONSE\n===============")
			stack.tunif.writetunippacket(tun,o,dump=True)
			print("")
	except stack.process.IgnorePacket as e:
		pass
	except BrokenPipeError as e:
		exit(0)
