#!/usr/bin/env python
import sys,os
import stack.utils
import stack.tapif
import stack.eth
import stack.ipv6
import stack.ipv4

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
myttl=8

def processEth(ethframe):
	print "\nRECEIVED ETH FRAME"
	print "Ethernet frame (assumed)"

	srcmac,dstmac = stack.eth.addresses(ethframe)
	print "MAC addresses {src} => {dst}".format(src=srcmac,dst=dstmac)
	ethertype = stack.eth.ethertype(ethframe)
	if ethertype < 1536:
		print "Non-Ethernet II frame"
	elif ethertype == stack.eth.IPV6TYPE:
		print "IPv6 packet"
		#o = processIP()
	elif ethertype == stack.eth.IPV4TYPE:
		print "IPv4 packet"
		ippacket = ethframe[stack.eth.PAYLOAD(ethframe):]
		o = processIP(ippacket)
		#if o is not None: stack.utils.writetunippacket(tun,o,dump=True)
	elif ethertype == stack.eth.VLANTYPE:
		print "VLAN encapsluated packet"
	elif ethertype == stack.eth.ARPTYPE:
		print "ARP packet"
		o = processARP(ethframe[stack.eth.PAYLOAD(ethframe):])
	else:
		print "Unknown ethertype {ty}".format(ty=hex(ethertype))

	print ""

def processARP(arpbuf):
	print "\nRECEIVED ARP PACKET"
	# TODO: ARP stuffing to set my IP (not actually something you do with ARP), Reply to all ARPs in the 169 autoip range to f* with it.
	
	htype = stack.eth.arphtype(arpbuf)
	ptype = stack.eth.arpptype(arpbuf)
	hlen  = stack.eth.arphlen(arpbuf)
	plen  = stack.eth.arpplen(arpbuf)
	opera = stack.eth.arpoperation(arpbuf)
	smac  = stack.eth.arpsendermacaddr(arpbuf)
	sip   = stack.eth.arpsenderipaddr(arpbuf)
	tmac  = stack.eth.arptargetmacaddr(arpbuf)
	tip   = stack.eth.arptargetipaddr(arpbuf)

	if opera == stack.eth.ARPREQUEST:
		opera = "request"
	elif opera == stack.eth.ARPREPLY:
		opera = "reply"
	print "htype", htype
	print "ptype", ptype
	print "hlen",hlen,"plen",plen
	print "opera", opera
	print "smac",smac
	print "sip", sip
	print "tmac",tmac
	print "tip",tip
	

def processIP(ippacket):
	print "\nRECEIVED IP PACKET"

	ipver = stack.utils.ipversion(ippacket)
	output = False

	if ipver == stack.ipv6.VERSION:
		print "IPv6 packet"
		length  = stack.ipv6.length(ippacket)
		nexthdr = stack.ipv6.nexthdr(ippacket)
		if nexthdr == stack.ipv6.ICMPTYPE:
			# ICMPv6
			type,code,name=stack.ipv6.icmpidentify(ippacket)
			body = stack.ipv6.icmpbody(ippacket)
			print "ICMPv6 {n} type {t} code {c}".format(n=name,t=type,c=code)
		else:
			print "IPv6 unknown next header value {nh}".format(nh=hex(nexthdr))
	elif ipver == stack.ipv4.VERSION:
		print "IPv4 packet"
		#for x in stack.utils.hexdump(ippacket): print x
		protocol = stack.ipv4.protocol(ippacket)
		srcaddr,dstaddr = stack.ipv4.addresses(ippacket)
		print "{s} => {d}".format(s=srcaddr,d=dstaddr)
		ttl = stack.ipv4.ipttl(ippacket)
		print "IP TTL ",ttl
	
		if protocol == stack.ipv4.ICMPTYPE:
			type,code,name = stack.ipv4.icmpidentify(ippacket)
			print "ICMPv4 {n} type {t} code {c}".format(n=name,t=type,c=code)
			if type == stack.ipv4.ICMPECHOREQUEST:
				# Modify it to an ICMP Echo Reply packet.
				if code != 0x0:
					print "ICMPv4 code is {code}, expected 0x0, ignoring descrepency".format(hex(code))
				print "\nResponding to ECHO REQUEST with ECHO RESPONSE"
				stack.ipv4.icmpechoresponse(ippacket)

				# Set TTL to my default (which should be based on how robust you think this code is :)
				stack.ipv4.set_ipttl(ippacket,myttl)

				# Since we are reusing this packet, then if we only swap IP 
				# addresses, we could just reuse previous checksum. But not if
				# we change, say, the TTL.
				s = stack.ipv4.ipcomputechecksum(ippacket)
				stack.ipv4.set_ipchecksum(ippacket,s)

				output = True

		elif protocol == stack.ipv4.TCPTYPE:
			srcport, dstport = stack.ipv4.tcpports(ippacket)
			print "TCP ports {src} => {dst}".format(src=srcport,dst=dstport)
	
			seqno,ackno = stack.ipv4.tcpseqackno(ippacket)
			print "TCP seqno {seq}".format(seq=hex(seqno))
			print "TCP ackno {ack}".format(ack=hex(ackno))

			hdrlen = stack.ipv4.tcphdrlen(ippacket)
			print "TCP hdrlen {hdr}".format(hdr=hdrlen)

			flags = stack.ipv4.tcpflags(ippacket)
			print "TCP flags {flags}".format(flags=hex(flags))

			f = stack.ipv4.tcpextractflags(flags)
			#print "TCP flags {s}".format(s=str(f))
			if f['syn']:
				print "\nResponding to TCP SYN with TCP RST"
				stack.ipv4.tcpsynrst(ippacket)

				# Set TTL to my default (which should be based on how robust you think this code is :)
				stack.ipv4.set_ipttl(ippacket,myttl)

				# Since we are reusing this packet, then if we only swap IP 
				# addresses, we could just reuse previous checksum. But not if
				# we change, say, the TTL.
				s = stack.ipv4.ipcomputechecksum(ippacket)
				stack.ipv4.set_ipchecksum(ippacket,s)

				output = True

		elif protocol == stack.ipv4.UDPTYPE:
			srcport, dstport = stack.ipv4.udpports(ippacket)
			print "UDP ports {src} => {dst}".format(src=srcport,dst=dstport)

			seglen = stack.ipv4.udpseglen(ippacket)
			print "UDP segment length {len}".format(len=seglen)

			if dstport == 67 and srcport == 68:
				print "DHCP client"
				stack.ipv4.dhcpparse(ippacket)
		else:
			print "IPv4 unknown protocol {prot}".format(prot=hex(protocol))
	else:
		print "Unknown / not an IP packet"

	print ""
	if output:
		return ippacket
	return None



tap = stack.tapif.bringuptap('192.168.7.1','192.168.7.2', name='tap0')
#tap = stack.tapif.bringuptap('DHCP','192.168.7.2', name='tap0')

while True:
	# Read an Ethernet frame been sent to this TAP device.
	ethframe = stack.tapif.readtapethframe(tap,dump=False)
	processEth(ethframe)
