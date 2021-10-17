#!/usr/bin/env python3
import sys,os
import stack.process
import stack.tapif

#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
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

hostip  = '192.168.7.1'
guestip = '192.168.7.2'

#guestmac = 'dc:a6:32:36:c4:01'
guestmac = 'aa:69:d1:7c:2e:a2'

if "dhcp" in sys.argv[0]:
	hostip = 'DHCP'

tap = stack.tapif.bringuptap(hostip, guestip, name='tap0')
pe  = stack.process.packetEngine(myipv4addr=guestip, mymacaddr=guestmac)

try:
	while True:
		# Read an Ethernet frame been sent to this TAP device.
		ethframe = stack.tapif.readtapethframe(tap,dump=False)
		try:
			# tap devices include Ethernet frames
			i, o = pe.processEth(ethframe)
			for l in i: print(l)
			print("============")
			if o is not None:
				stack.tapif.writetapethframe(tap,o, dump=True)
				print("############")
		except stack.process.IgnorePacket as e:
			pass
except BrokenPipeError as e:
	exit(0)
except KeyboardInterrupt as e:
	exit(o)
