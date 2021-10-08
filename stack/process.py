#!/usr/bin/env python

#####
# WARNING
# Nothing in this file should be considered part of the API. This is 
# currently just a bunch of mostly nailed-up packet decoders. The
# intention is that somehow I'll design modular engines that can
# implement complex protocol behaviors (e.g. such as TCP) while somehow
# remaining modular and modifiable so as to be customizable. Right now you
# get custom behavior by forking this file and modifying it directly.
#####

import sys,os
from . import utils
from . import eth
from . import ipv6
from . import ipv4

def processEth(ethframe,processIP=None,respondIP=None,processARP=None,respondARP=None):
	print("\nRECEIVED ETH FRAME")
	print("Ethernet frame (assumed)")

	srcmac,dstmac = eth.addresses(ethframe)
	print("MAC addresses {src} => {dst}".format(src=srcmac,dst=dstmac))
	ethertype = eth.ethertype(ethframe)
	o=None
	if ethertype < 1536:
		print("Non-Ethernet II frame")
	elif ethertype == eth.IPV6TYPE:
		print("IPv6 packet, skipping")
		#o = processIP()
	elif ethertype == eth.IPV4TYPE:
		print("IPv4 packet")
		ippacket = ethframe[eth.PAYLOAD(ethframe):]
		if processIP is not None:
			o = processIP(ippacket)
		if respondIP is not None and o is not None: 
			respondIP(o)
	elif ethertype == eth.VLANTYPE:
		print("VLAN encapsluated packet, skipping")
	elif ethertype == eth.ARPTYPE:
		print("ARP packet")
		if processARP is not None:
			o = processARP(ethframe[eth.PAYLOAD(ethframe):])
		if respondARP is not None and o is not None: 
			respondARP(o)
	else:
		print("Unknown ethertype {ty}".format(ty=hex(ethertype)))

	print("")

def processARP(arpbuf):
	print("\nRECEIVED ARP PACKET")
	# TODO: ARP stuffing to set my IP (not actually something you do with ARP), Reply to all ARPs in the 169 autoip range to f* with it.
	
	htype = eth.arphtype(arpbuf)
	ptype = eth.arpptype(arpbuf)
	hlen  = eth.arphlen(arpbuf)
	plen  = eth.arpplen(arpbuf)
	opera = eth.arpoperation(arpbuf)
	smac  = eth.arpsendermacaddr(arpbuf)
	sip   = eth.arpsenderipaddr(arpbuf)
	tmac  = eth.arptargetmacaddr(arpbuf)
	tip   = eth.arptargetipaddr(arpbuf)

	if opera == eth.ARPREQUEST:
		opera = "request"
	elif opera == eth.ARPREPLY:
		opera = "reply"
	print("htype {}".format(htype))
	print("ptype {}".format(ptype))
	print("hlen  {} plen {}".format(hlen,plen))
	print("opera {}".format(opera))
	print("smac  {}".format(smac))
	print("sip   {}".format(sip))
	print("tmac  {}".format(tmac))
	print("tip   {}".format(tip))
	

def processIP(ippacket,myttl=8):
	print("\nRECEIVED IP PACKET")

	ipver = utils.ipversion(ippacket)
	output = False

	if ipver == ipv6.VERSION:
		print("IPv6 packet")
		#for x in utils.hexdump(ippacket): print(x)
		length  = ipv6.length(ippacket)
		nexthdr = ipv6.nexthdr(ippacket)
		if nexthdr == ipv6.ICMPTYPE:
			# ICMPv6
			type,code,name=ipv6.icmpidentify(ippacket)
			body = ipv6.icmpbody(ippacket)
			print("ICMPv6 {n} type {t} code {c}".format(n=name,t=type,c=code))
		else:
			print("IPv6 unhandled next header value {nh}".format(nh=hex(nexthdr)))
	elif ipver == ipv4.VERSION:
		print("IPv4 packet")
		#for x in utils.hexdump(ippacket): print(x)
		protocol = ipv4.protocol(ippacket)
		srcaddr,dstaddr = ipv4.addresses(ippacket)
		print("{s} => {d}".format(s=srcaddr,d=dstaddr))
		ttl = ipv4.ipttl(ippacket)
		print("IP TTL {}".format(ttl))
	
		if protocol == ipv4.ICMPTYPE:
			type,code,name = ipv4.icmpidentify(ippacket)
			print("ICMPv4 {n} type {t} code {c}".format(n=name,t=type,c=code))
			if type == ipv4.ICMPECHOREQUEST:
				# Modify it to an ICMP Echo Reply packet.
				if code != 0x0:
					print("ICMPv4 code is {code}, expected 0x0, ignoring descrepency".format(hex(code)))
				print("\nResponding to ECHO REQUEST with ECHO RESPONSE")
				ipv4.icmpechoresponse(ippacket)

				# Set TTL to my default (which should be based on how robust you think this code is :)
				ipv4.set_ipttl(ippacket,myttl)

				# Since we are reusing this packet, then if we only swap IP 
				# addresses, we could just reuse previous checksum. But not if
				# we change, say, the TTL.
				s = ipv4.ipcomputechecksum(ippacket)
				ipv4.set_ipchecksum(ippacket,s)

				output = True

		elif protocol == ipv4.TCPTYPE:
			srcport, dstport = ipv4.tcpports(ippacket)
			print("TCP ports {src} => {dst}".format(src=srcport,dst=dstport))
	
			seqno,ackno = ipv4.tcpseqackno(ippacket)
			print("TCP seqno {seq}".format(seq=hex(seqno)))
			print("TCP ackno {ack}".format(ack=hex(ackno)))

			hdrlen = ipv4.tcphdrlen(ippacket)
			print("TCP hdrlen {hdr}".format(hdr=hdrlen))

			flags = ipv4.tcpflags(ippacket)
			print("TCP flags {flags}".format(flags=hex(flags)))

			f = ipv4.tcpextractflags(flags)
			#print("TCP flags {s}".format(s=str(f)))
			if f['syn']:
				print("\nResponding to TCP SYN with TCP RST")
				ipv4.tcpsynrst(ippacket)

				# Set TTL to my default (which should be based on how robust you think this code is :)
				ipv4.set_ipttl(ippacket,myttl)

				# Since we are reusing this packet, then if we only swap IP 
				# addresses, we could just reuse previous checksum. But not if
				# we change, say, the TTL.
				s = ipv4.ipcomputechecksum(ippacket)
				ipv4.set_ipchecksum(ippacket,s)

				output = True

		elif protocol == ipv4.UDPTYPE:
			srcport, dstport = ipv4.udpports(ippacket)
			print("UDP ports {src} => {dst}".format(src=srcport,dst=dstport))

			seglen = ipv4.udpseglen(ippacket)
			print("UDP segment length {len}".format(len=seglen))

			if dstport == 67 and srcport == 68:
				print("DHCP client")
				ipv4.dhcpparse(ippacket)
		else:
			print("IPv4 unknown protocol {prot}".format(prot=hex(protocol)))
	else:
		print("Unknown / not an IP packet")

	print("")
	if output:
		return ippacket
	return None


