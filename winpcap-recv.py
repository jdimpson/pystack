#!/usr/bin/env python
import stack.winpcapyif
import stack.utils
import stack.process

winp = stack.winpcapyif.bringupwinpcapy("Microsoft")

while True:
        c,p = stack.winpcapyif.readwinpcapyethpacket(winp,dump=True,cnt=True)
        info, out = stack.process.processEth(p,processIP=stack.process.processIP,processARP=stack.process.processARP)
        print('\n'.join(info))
        print("==============")
