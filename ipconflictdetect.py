#!/usr/bin/env python3
import sys,os
import stack.rawif
import stack.eth
import stack.process
import stack.utils
from time import time, sleep
from random import randrange

# Address Conflict Resolution
# per https://www.rfc-editor.org/rfc/rfc5227

alen = len(sys.argv)
if alen > 1:
	targetip = sys.argv[1]
else:
	targetip = '10.0.0.5'

if alen > 2:
	iface = sys.argv[2]
else:
	iface = "eth0"

if alen > 3:
	mymac = sys.argv[3]
else:
	mymac = 'de:ad:ba:be:ee:ee'

zeroip = '0.0.0.0'
bcastmac  =  0xffffffffffff

print("Sending an ARP Probe packet with Sender MAC {smac}, Sender IP {sip}, Target MAC {tmac}, and Target IP {tip}".format(smac=mymac, sip=zeroip, tmac=bcastmac, tip=targetip))

# A host probes to see if an address is already in use by broadcasting an ARP Request for the desired address.  The client MUST fill in the
# 'sender hardware address' field of the ARP Request with the hardware address of the interface through which it is sending the packet.  The
# 'sender IP address' field MUST be set to all zeroes; this is to avoid polluting ARP caches in other hosts on the same link in the case
# where the address turns out to be already in use by another host.  The 'target hardware address' field is ignored and SHOULD be set to
# all zeroes.  The 'target IP address' field MUST be set to the address being probed.  An ARP Request constructed this way, with an all-zero
# 'sender IP address', is referred to as an 'ARP Probe'.

raw = stack.rawif.bringupraw(iface=iface,promisc=True)
ethhdr = stack.eth.makeethIIhdr(bcastmac,mymac,typ=stack.eth.ARPTYPE)
arpbuf = stack.eth.makearpbuf(mymac, zeroip, bcastmac, targetip, oper=stack.eth.ARPREQUEST)
frame = ethhdr + arpbuf

# When ready to begin probing, the host should then wait for a random time interval selected uniformly in the range zero to PROBE_WAIT
# seconds, and should then send PROBE_NUM probe packets, each of these probe packets spaced randomly and uniformly, PROBE_MIN to PROBE_MAX
# seconds apart.  This initial random delay helps ensure that a large number of hosts powered on at the same time do not all send their
# initial probe packets simultaneously.

w = randrange(0,stack.eth.ARP_PROBE_WAIT)
print("Sleeping {} seconds".format(w))
sleep(w)
available = True
for n in range(0,stack.eth.ARP_PROBE_NUM):
	print("Sending probe {}/{}".format(n,stack.eth.ARP_PROBE_NUM))
	sentat = time()
	stack.rawif.writerawethframe(raw,frame)
	while sentat + stack.eth.ARP_ANNOUNCE_WAIT > time():
		# XXX: need to implement timeout
		ethframe = stack.rawif.readrawethframe(raw)
		if not stack.eth.dstfilter(mymac,ethframe,asbytes=True) and not stack.eth.dstfilter(bcastmac,ethframe,asbytes=True):
			continue
		if stack.eth.ethertype(ethframe) != stack.eth.ARPTYPE:
			continue
		if stack.eth.srcfilter(mymac,ethframe,asbytes=True):
			print("Received my own frame back at me?!")
			continue

		arpbuf = ethframe[stack.eth.PAYLOAD(ethframe):]
		# If during this period, from the beginning of the probing process until ANNOUNCE_WAIT seconds after the last probe packet
		# is sent, the host receives any ARP packet (Request *or* Reply) on the interface where the probe is being performed, where
		# the packet's 'sender IP address' is the address being probed for, then the host MUST treat this address as being in use by
		# some other host, and should indicate to the configuring agent (human operator, DHCP server, etc.) that the proposed
		# address is not acceptable.
		if targetip == stack.eth.arpsenderipaddr(arpbuf):
			available = False
			break
		# In addition, if during this period the host receives any ARP Probe where the packet's 'target IP address' is the address
		# being probed for, and the packet's 'sender hardware address' is not the hardware address of any of the host's interfaces,
		# then the host SHOULD similarly treat this as an address conflict and signal an error to the configuring agent as above.
		# This can occur if two (or more) hosts have, for whatever reason, been inadvertently configured with the same address, and
		# both are simultaneously in the process of probing that address to see if it can safely be used.
		if targetip == stack.eth.arptargetipaddr(arpbuf):
			available = False
			break
	if not available:
		break
	sleep(randrange(stack.eth.ARP_PROBE_MIN, stack.eth.ARP_PROBE_MAX))
if not available:
	print('{} is NOT available!'.format(targetip))
	exit(1)

# Having probed to determine that a desired address may be used safely, a host implementing this specification MUST then announce that it
# is commencing to use this address by broadcasting ANNOUNCE_NUM ARP Announcements, spaced ANNOUNCE_INTERVAL seconds apart.  An ARP
# Announcement is identical to the ARP Probe described above, except that now the sender and target IP addresses are both set to the
# host's newly selected IPv4 address.  The purpose of these ARP Announcements is to make sure that other hosts on the link do not
# have stale ARP cache entries left over from some other host that may previously have been using the same address.  The host may begin
# legitimately using the IP address immediately after sending the first of the two ARP Announcements; the sending of the second ARP
# Announcement may be completed asynchronously, concurrent with other networking operations the host may wish to perform.
arpbuf = stack.eth.makearpbuf(mymac, targetip, bcastmac, targetip, oper=stack.eth.ARPREQUEST)
frame = ethhdr + arpbuf

for n in range(0,stack.eth.ARP_ANNOUNCE_NUM):
	print("Sending Announcement {}/{}".format(n,stack.eth.ARP_ANNOUNCE_NUM))
	stack.rawif.writerawethframe(raw,frame)
	sleep(stack.eth.ARP_ANNOUNCE_INTERVAL)

print("Detecting conflicts")
# Address Conflict Detection is not limited to only the time of initial interface configuration, when a host is sending ARP Probes.  Address
# Conflict Detection is an ongoing process that is in effect for as long as a host is using an address.  At any time, if a host receives
# an ARP packet (Request *or* Reply) where the 'sender IP address' is (one of) the host's own IP address(es) configured on that interface,
# but the 'sender hardware address' does not match any of the host's own interface addresses, then this is a conflicting ARP packet,
# indicating some other host also thinks it is validly using this address.  
while True:
	ethframe = stack.rawif.readrawethframe(raw)
	if not stack.eth.dstfilter(mymac,ethframe,asbytes=True) and not stack.eth.dstfilter(bcastmac,ethframe,asbytes=True):
		continue
	if stack.eth.ethertype(ethframe) != stack.eth.ARPTYPE:
		continue
	if stack.eth.srcfilter(mymac,ethframe,asbytes=True):
		print("Received my own frame back at me?!")
		continue
	arpbuf = ethframe[stack.eth.PAYLOAD(ethframe):]

	print("frame")
	if targetip == stack.eth.arpsenderipaddr(arpbuf):
		othermac = stack.eth.arpsendermacaddr(arpbuf)
		if mymac != othermac:
			print("IP CONFLICT for {} with {}".format(targetip, othermac))
		else:
			print("Everything is fine.")

	elif targetip == stack.eth.arptargetipaddr(arpbuf):
		print("ARP REPLY NEEDED")
# for x in stack.utils.hexdump(ethframe): print(x)
exit(0)
