#!/usr/bin/env python
import sys,os
import stack.process
import stack.tapif

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

if "dhcp" in sys.argv[0]:
	tap = stack.tapif.bringuptap('DHCP','192.168.7.2', name='tap0')
else:
	tap = stack.tapif.bringuptap('192.168.7.1','192.168.7.2', name='tap0')

while True:
	# Read an Ethernet frame been sent to this TAP device.
	ethframe = stack.tapif.readtapethframe(tap,dump=False)
	stack.process.processEth(ethframe,processIP=stack.process.processIP,processARP=stack.process.processARP)
