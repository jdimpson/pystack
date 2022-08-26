#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.eth
import stack.process
import stack.utils

# from https://www.rfc-editor.org/rfc/rfc5227
# In this document, the term 'ARP Announcement' is used to refer to an ARP Request packet, broadcast on the local link, identical to the ARP
# Probe described above, except that both the sender and target IP address fields contain the IP address being announced.  It conveys a
# stronger statement than an ARP Probe, namely, "This is the address I am now using."



alen = len(sys.argv)
if alen > 1:
	dstip = srcip  = sys.argv[1]
else:
	dstip = srcip  = '10.0.0.5'

if alen > 2:
	iface = sys.argv[2]
else:
	iface = "eth0"

if alen > 3:
	srcmac = sys.argv[3]
else:
	srcmac = 'aa:bb:cc:dd:ee:ff'

dstmac =  0x000000000000

print("Sending a gratuitious ARP packet with Sender MAC {smac}, Sender IP {sip}, Target MAC {tmac}, and Target IP {tip}".format(smac=srcmac, sip=srcip, tmac=dstmac, tip=dstip))

raw = stack.rawif.bringupraw(iface=iface,promisc=True)
ethhdr = stack.eth.makeethIIhdr(dstmac,srcmac,typ=stack.eth.ARPTYPE)
arpbuf = stack.eth.makearpbuf(srcmac, srcip, dstmac, dstip, oper=stack.eth.ARPREQUEST)
frame = ethhdr + arpbuf

# raw ethernet sockets apparently still compute the CRC so this isn't needed.
#crc = stack.eth.CRC32(frame)
#frame = frame + crc.to_bytes(4, byteorder='big')

for x in stack.utils.hexdump(frame):
	print(x)
stack.rawif.writerawethframe(raw,frame)

exit(0)
