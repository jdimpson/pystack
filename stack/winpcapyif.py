#!/usr/bin/env python
# https://github.com/orweis/winpcapy
from winpcapy import WinPcapUtils,WinPcapDevices

from queue import SimpleQueue
from threading import Thread

from . import utils

def listwinpcapyifaces():
    with WinPcapDevices() as devices:
        for device in devices:
            yield device.name, device.description, device.flags ,device.addresses.contents.netmask.contents.sa_family
    #return WinPcapDevices.list_devices()

def bringupwinpcapy(iface,recv=True,dump=False):
    q = SimpleQueue()
    c = 0
    def packet_callback(win_pcap, param, header, pkt_data):
        nonlocal c # winpcapy only works on python3 so *shrug*
        if dump:
            print("pkt len {}".format(len(pkt_data)))
        q.put((c,pkt_data))
        c+=1
    t=Thread(target=lambda:WinPcapUtils.capture_on(iface, packet_callback),daemon=True)
    if recv:
        t.start()
    return (t,q,iface)

def readwinpcapyethpacket(winp, dump=False, cnt=False):
    t=winp[0] # thread obj
    if not t.is_alive():
        raise RuntimeError("winp object not configured for recv")
    q=winp[1]
    #i=winp[2] # interface name
    o=q.get()
    c=o[0]
    p=bytearray(o[1])
    if dump:
        for x in utils.hexdump(p):
            print(x)
    if cnt:
        return (c,p)
    else:
        return p

def writewinpcapyethpacket(winp, ethpacket, dump=False):
    i=winp[2]
    if dump:
        for x in utils.hexdump(ethpacket):
            print(x)
    WinPcapUtils.send_packet(i,ethpacket)
