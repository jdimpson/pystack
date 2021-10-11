#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.process

#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
iface = "eth0"

if len(sys.argv) > 1:
	iface = sys.argv[1]

raw = stack.rawif.bringupraw(iface=iface,promisc=True)

while True:
	# Read an Ethernet frame that's been sent to this device.
	ethframe = stack.rawif.readrawethframe(raw)
	info,out = stack.process.processEth(ethframe,processIP=stack.process.processIP,processARP=stack.process.processARP)
	print('\n'.join(info))
	print("============")
	for o in out:
		stack.rawif.writerawethframe(raw,o)
