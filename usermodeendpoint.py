#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.process

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

iface = "eth0"

if len(sys.argv) > 1:
	iface = sys.argv[1]

raw = stack.rawif.bringupraw(iface=iface,promisc=True)
mymac = "aa:bb:cc:cc:bb:aa"
bcast = "ff:ff:ff:ff:ff:ff"
pe = stack.process.packetEngine(myipv4addr="10.0.0.5", mymacaddr=mymac)
while True:
	# Read an Ethernet frame that's been sent to this device.
	ethframe = stack.rawif.readrawethframe(raw)
	if not stack.eth.dstfilter(mymac,ethframe,asbytes=True) and not stack.eth.dstfilter(bcast,ethframe,asbytes=True): 
		print("skip")
		continue
	try:
		info,out = pe.processEth(ethframe)
		for i in info: print(i)
		print("============")
		if out:
			stack.rawif.writerawethframe(raw,out, dump=True)
			print("############")
	except stack.process.IgnorePacket as e:
		pass
	except BrokenPipeError as e:
		exit(0)
