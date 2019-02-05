#!/usr/bin/env python
import codecs

import stack.winpcapyif
import stack.utils
import stack.process

winp = stack.winpcapyif.bringupwinpcapy("Microsoft", recv=True)

arp_request_hex_template = "%(dst_mac)s%(src_mac)s08060001080006040001" \
                           "%(sender_mac)s%(sender_ip)s%(target_mac)s%(target_ip)s" + "00" * 18
packet = bytearray(arp_request_hex_template % {
    "dst_mac": "68c44da8f91a",
    "src_mac": "34f39a8e2966",
    "sender_mac": "34f39a8e2966",
    "target_mac": "68c44da8f91a",
    # 192.168.0.1
    "sender_ip": "c0a82b11",
    # 192.168.0.2
    "target_ip": "c0a82b01"
} ,'utf-8')

# Send the packet (ethernet frame with an arp request) on the interface
stack.winpcapyif.writewinpcapyethpacket(winp, codecs.decode(packet,'hex'),dump=True)

while True:
        p = stack.winpcapyif.readwinpcapyethpacket(winp,dump=True)
        stack.process.processEth(p,processIP=stack.process.processIP,processARP=stack.process.processARP)
        print("==============")
