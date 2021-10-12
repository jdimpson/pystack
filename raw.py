#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.process

#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
iface = "eth0"

if len(sys.argv) > 1:
	iface = sys.argv[1]

raw = stack.rawif.bringupraw(iface=iface,promisc=True)

pe = stack.process.packetEngine()
while True:
	# Read an Ethernet frame that's been sent to this device.
	ethframe = stack.rawif.readrawethframe(raw)
	try:
		info,out = pe.processEth(ethframe)
		for i in info: print(i)
		print("============")
		if out:
			stack.rawif.writerawethframe(raw,out)
			print("############")
	except stack.process.IgnorePacket as e:
		pass
	except BrokenPipeError as e:
		exit(0)
