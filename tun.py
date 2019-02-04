#!/usr/bin/env python
import stack.utils
import stack.tunif
import stack.ipv6
import stack.ipv4

myttl=8

tun = stack.tunif.bringuptun('192.168.7.1','192.168.7.2', name='tun0')

while True:
	# Read an IP packet been sent to this TUN device.
	ippacket = stack.tunif.readtunippacket(tun)

	print "\nRECEIVED NEW PACKET"
	for x in stack.utils.hexdump(ippacket):
		print x 

	ipver = stack.utils.ipversion(ippacket)

	if ipver == stack.ipv6.VERSION:
		print "IPv6 packet"
		length  = stack.ipv6.length(ippacket)
		nexthdr = stack.ipv6.nexthdr(ippacket)
		#print stack.utils.hexlify(''.join(ippacket[stack.ipv6.PAYLOAD:]))
		if nexthdr == stack.ipv6.ICMPTYPE:
			# ICMPv6
			type,code,name=stack.ipv6.icmpidentify(ippacket)
			body = stack.ipv6.icmpbody(ippacket)
			print "ICMPv6 {n} type {t} code {c}".format(n=name,t=type,c=code)
		else:
			print "IPv6 unknown next header value {nh}".format(nh=hex(nexthdr))
	elif ipver == stack.ipv4.VERSION:
		print "IPv4 packet"
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

				stack.tunif.writetunippacket(tun,ippacket,dump=True)

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

				stack.tunif.writetunippacket(tun,ippacket,dump=True)

		else:
			print "IPv4 unknown protocol {prot}".format(prot=hex(protocol))
	else:
		print "Unknown / not an IP packet"


	print ""
