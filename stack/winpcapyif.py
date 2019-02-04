#!/usr/bin/env python
# https://github.com/orweis/winpcapy
from winpcapy import WinPcapUtils,WinPcapDevices

from queue import SimpleQueue
from threading import Thread

from . import utils


def listwinpcapyifaces():
        return WinPcapDevices.list_devices()

def bringupwinpcapy(iface,dump=False):
        q = SimpleQueue()
        c = 0
        def packet_callback(win_pcap, param, header, pkt_data):
            nonlocal c # winpcapy only works on python3 so *shrug*
            if dump:
                print("pkt len {}".format(len(pkt_data)))
            q.put((c,pkt_data))
            c+=1
        t=Thread(target=lambda:WinPcapUtils.capture_on(iface, packet_callback))
        t.start()
        return (t,q)

def readwinpcapyethpacket(winp, dump=False, cnt=False):
        #t=winp[0] # thread obj
        q=winp[1]
        o=q.get()
        c=o[0]
        p=o[1]
        if dump:
            for x in utils.hexdump(p):
                print(x)
        if cnt:
            return (c,p)
        else:
            return p
