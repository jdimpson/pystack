#!/usr/bin/env python
import stack.winpcapyif
import stack.utils

winp = stack.winpcapyif.bringupwinpcapy("Microsoft")

while True:
        c,p = stack.winpcapyif.readwinpcapyethpacket(winp,dump=True,cnt=True)
        print("{}\n==============".format(c))
