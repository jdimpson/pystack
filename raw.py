#!/usr/bin/env python
import sys,os
import stack.rawif
import stack.process

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

raw = stack.rawif.bringupraw()

while True:
	# Read an Ethernet frame been sent to this device.
	ethframe = stack.rawif.readrawethframe(raw)
	stack.process.processEth(ethframe,processIP=stack.process.processIP,processARP=stack.process.processARP)
