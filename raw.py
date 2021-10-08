#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.process

#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

raw = stack.rawif.bringupraw(promisc=True)

while True:
	# Read an Ethernet frame been sent to this device.
	ethframe = stack.rawif.readrawethframe(raw)
	info,out = stack.process.processEth(ethframe,processIP=stack.process.processIP,processARP=stack.process.processARP)
	print('\n'.join(info))
	print("============")
