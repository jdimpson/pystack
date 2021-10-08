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
	info = []
	info.append("RECEIVED ETH FRAME")
	info.append("Ethernet frame (assumed)")
	out = []

	srcmac,dstmac = eth.addresses(ethframe)
	info.append("MAC addresses {src} => {dst}".format(src=srcmac,dst=dstmac))
	ethertype = eth.ethertype(ethframe)
	o=None
	if ethertype < 1536:
		info.append("Non-Ethernet II frame")
	elif ethertype == eth.IPV6TYPE:
		info.append("IPv6 packet")
		ippacket = ethframe[eth.PAYLOAD(ethframe):]
		if processIP is not None:
			i,o = processIP(ippacket)
			for j in i: info.append(j)
			for j in o: out.append(o)
		if respondIP is not None and o is not None: 
			respondIP(o)
	elif ethertype == eth.IPV4TYPE:
		info.append("IPv4 packet")
		ippacket = ethframe[eth.PAYLOAD(ethframe):]
		if processIP is not None:
			i,o = processIP(ippacket)
			for j in i: info.append(j)
			for j in o: out.append(o)
		if respondIP is not None and o is not None: 
			respondIP(o)
	elif ethertype == eth.VLANTYPE:
		info.append("VLAN encapsluated packet, skipping")
	elif ethertype == eth.ARPTYPE:
		info.append("ARP packet")
		if processARP is not None:
			i,o = processARP(ethframe[eth.PAYLOAD(ethframe):])
			for j in i: info.append(j)
			for j in o: out.append(o)
		if respondARP is not None and o is not None: 
			respondARP(o)
	else:
		info.append("Unknown ethertype {ty}".format(ty=hex(ethertype)))

	return info,out

def processARP(arpbuf):
	info = []
	info.append("RECEIVED ARP PACKET")
	out = []
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
	info.append("htype {}".format(htype))
	info.append("ptype {}".format(ptype))
	info.append("hlen  {} plen {}".format(hlen,plen))
	info.append("opera {}".format(opera))
	info.append("smac  {}".format(smac))
	info.append("sip   {}".format(sip))
	info.append("tmac  {}".format(tmac))
	info.append("tip   {}".format(tip))
	return info, out

def processIP(ippacket,myttl=8):
	info = []
	info.append("RECEIVED IP PACKET")
	out = []

	ipver = utils.ipversion(ippacket)
	output = False

	if ipver == ipv6.VERSION:
		info.append("IPv6 packet")
		length  = ipv6.length(ippacket)
		nexthdr = ipv6.nexthdr(ippacket)
		info.append("length {}, nexthdr {}".format(length, nexthdr))
		if nexthdr == ipv6.ICMPTYPE:
			# ICMPv6
			type,code,name=ipv6.icmpidentify(ippacket)
			body = ipv6.icmpbody(ippacket)
			info.append("ICMPv6 {n} type {t} code {c}".format(n=name,t=type,c=code))
		if nexthdr == ipv6.UDPTYPE:
			info.append("UDP message")
		else:
			info.append("IPv6 unhandled next header value {nh}".format(nh=hex(nexthdr)))
	elif ipver == ipv4.VERSION:
		info.append("IPv4 packet")
		#for x in utils.hexdump(ippacket): print(x)
		protocol = ipv4.protocol(ippacket)
		srcaddr,dstaddr = ipv4.addresses(ippacket)
		info.append("{s} => {d}".format(s=srcaddr,d=dstaddr))
		ttl = ipv4.ipttl(ippacket)
		info.append("IP TTL {}".format(ttl))
	
		if protocol == ipv4.ICMPTYPE:
			type,code,name = ipv4.icmpidentify(ippacket)
			info.append("ICMPv4 {n} type {t} code {c}".format(n=name,t=type,c=code))
			if type == ipv4.ICMPECHOREQUEST:
				# Modify it to an ICMP Echo Reply packet.
				if code != 0x0:
					info.append("ICMPv4 code is {code}, expected 0x0, ignoring descrepency".format(hex(code)))
				info.append("Responding to ECHO REQUEST with ECHO RESPONSE")
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
			info.append("TCP ports {src} => {dst}".format(src=srcport,dst=dstport))
	
			seqno,ackno = ipv4.tcpseqackno(ippacket)
			info.append("TCP seqno {seq}".format(seq=hex(seqno)))
			info.append("TCP ackno {ack}".format(ack=hex(ackno)))

			hdrlen = ipv4.tcphdrlen(ippacket)
			info.append("TCP hdrlen {hdr}".format(hdr=hdrlen))

			flags = ipv4.tcpflags(ippacket)
			info.append("TCP flags {flags}".format(flags=hex(flags)))

			f = ipv4.tcpextractflags(flags)
			#info.append("TCP flags {s}".format(s=str(f)))
			if f['syn']:
				info.append("Responding to TCP SYN with TCP RST")
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
			info.append("UDP ports {src} => {dst}".format(src=srcport,dst=dstport))

			seglen = ipv4.udpseglen(ippacket)
			info.append("UDP segment length {len}".format(len=seglen))

			if dstport == 67 and srcport == 68:
				info.append("DHCP client")
				ipv4.dhcpparse(ippacket)
		else:
			info.append("IPv4 unknown protocol {prot}".format(prot=hex(protocol)))
	else:
		info.append("Unknown / not an IP packet")

	# XXX: this will get messy real quick; need to not reuse input buffer
	if output:
		out.append(ippacket)
	return info,out


