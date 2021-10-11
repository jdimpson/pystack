#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.eth
import stack.process
import stack.utils

iface = "eth0"

raw = stack.rawif.bringupraw(iface=iface,promisc=True)

#dstmac = 187723572702975
dstmac =  0xffffffffffff
srcmac = 'aa:bb:cc:dd:ee:ff'
ethhdr = stack.eth.makeethIIhdr(dstmac,srcmac,typ=0x9000)
nullbody = bytearray([ 0 for x in range(46) ])
frame = ethhdr + nullbody
crc = stack.eth.CRC32(frame)
frame = frame + crc.to_bytes(4, byteorder='big')
#print(frame,len(frame))
for x in stack.utils.hexdump(frame):
	print(x)
stack.rawif.writerawethframe(raw,frame)
