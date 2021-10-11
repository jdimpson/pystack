#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.eth
import stack.process

iface = "eth0"


raw = stack.rawif.bringupraw(iface=iface,promisc=True)

dstmac = 187723572702975
srcmac = 'aa:bb:cc:dd:ee:ff'
ethhdr = stack.eth.makeethIIhdr(dstmac,srcmac)

#stack.rawif.writerawethframe(raw,o)
