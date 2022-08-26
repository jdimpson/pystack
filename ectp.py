#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.eth
import stack.process
import stack.utils

# https://aminems.github.io/ctp.html

iface = "eth0"

raw = stack.rawif.bringupraw(iface=iface,promisc=True)

LOOPBACKASSISTMAC = 'cf:00:00:00:00:00'

#dstmac = 187723572702975
dstmac =  0xffffffffffff
srcmac = 'aa:bb:cc:dd:ee:ff'
ethhdr = stack.eth.makeethIIhdr(dstmac,srcmac,typ=0x9000)
nullbody = bytearray([ 0 for x in range(46) ])
frame = ethhdr + nullbody

# raw ethernet sockets apparently still compute the CRC so this isn't needed.
#crc = stack.eth.CRC32(frame)
#frame = frame + crc.to_bytes(4, byteorder='big')

for x in stack.utils.hexdump(frame):
	print(x)
stack.rawif.writerawethframe(raw,frame)

exit(0)
