from .utils import get_bytes

VERSION=6
ICMPTYPE=0x3a
PAYLOAD=40 # TODO: figure out how extension headers are supposed to work

def length(ippacket):
	return (get_bytes(ippacket,4,5)[0]  << 8)| (get_bytes(ippacket,5,6)[0])
	#return ( ord(ippacket[4:5][0])  << 8 )| ord( ippacket[5:6][0] )

def nexthdr(ippacket):
	return get_bytes(ippacket,4,5)[0]
	#return ord( ippacket[6:7][0])

def icmptype(ippacket):
	return ord(  ippacket[PAYLOAD:][0:1][0] )
def icmpcode(ippacket):
	return ord(  ippacket[PAYLOAD:][1:2][0] )

def icmpbody(ippacket):
	return ippacket[PAYLOAD:][32:]

def icmpidentify(ippacket):
	type = icmptype(ippacket)
	code = icmpcode(ippacket)
	name = "unknown type/code pair"

	if type == 133 and code == 0:
		name = "Router Solicitation"
	return type,code,name	

#			else:
#				print("ICMPv6 unknown type {t} code {c}".format(t=type,c=code))
#				print(myhexlify(''.join(body)))
#		else:
#			print("IPv6: unknown next header {nh}".format(nh=hex(nexthdr)))
#	elif ipver == 4:
#		print("IPv4 packet")
#		ihl   = ord(ippacket[0:1][0]) & 0xF
#		iphdr = ihl * 4
#		#print("ippayload: ",[hex(ord(x)) for x in ippacket[iphdr:]])
#		protocol = ord(ippacket[9:10][0])
#	
#		if protocol == 0x1:
#			# ICMP
#			type = ord(ippacket[iphdr:][0:1][0])
#			code = ord(ippacket[iphdr:][1:2][0])
#			if type == 0x8: # Echo request
#				print("ICMPv4 Echo Request")
#				# Modify it to an ICMP Echo Reply packet.
#	
#				if code != 0x0:
#					print("ICMP: code is {code}, expected 0x0, ignoring descrepency".format(hex(code)))
#	
#				# Swap source and destination address.
#				ippacket[12:16], ippacket[16:20] = ippacket[16:20], ippacket[12:16]
#	
#				# Under Linux, the code below is not necessary to make the TUN device to
#				# work. I don't know why yet. If you run tcpdump, you can see the
#				# difference.
#				# Change ICMP type code to Echo Reply (0).
#				ippacket[20] = chr(0)
#				# Clear original ICMP Checksum field.
#				ippacket[22:24] = chr(0), chr(0)
#				# Calculate new checksum.
#				checksum = 0
#				# for every 16-bit of the ICMP payload:
#				for i in range(20, len(ippacket), 2):
#					half_word = (ord(ippacket[i]) << 8) + ord(ippacket[i+1])
#					checksum += half_word
#				# Get one's complement of the checksum.
#				checksum = ~(checksum + 4) & 0xffff
#				# Put the new checksum back into the packet.
#				ippacket[22] = chr(checksum >> 8)
#				ippacket[23] = chr(checksum & ((1 << 8) -1))
#	
#				do_write = True
#			else:
#				print("ICMP: unknown type {type}".format(type=hex(type)))
#		elif protocol == 0x6:
#			# TCP
#	
#			# ports
#			h,l = [ord(x) for x in ippacket[iphdr:][0:2]]
#			srcport = h<<8 | l
#			h,l = [ord(x) for x in ippacket[iphdr:][2:4]]
#			dstport = h<<8 | l
#			print("TCP ports {src} => {dst}".format(src=srcport,dst=dstport))
#	
#			# sequence and ACK
#			h,m,f,l = [ord(x) for x in ippacket[iphdr:][4:8]]
#			seqno = (h<<24)|(m<<16)|(f<<8)|l
#			print("TCP seqno {seq}".format(seq=seqno))
#			h,m,f,l = [ord(x) for x in ippacket[iphdr:][8:12]]
#			ackno = (h<<24)|(m<<16)|(f<<8)|l
#			print("TCP ackno {ack}".format(ack=ackno))
#	
#			# flags
#			h,l = [ord(x) for x in ippacket[iphdr:][12:14]]
#			offset = (h & 0xf0) >> 4
#			flags  = (h & 0x01) << 8 | l
#			ns  = bool((flags & 0x0100) >> 8)
#			cwr = bool((flags & 0x0080) >> 7)
#			ece = bool((flags & 0x0040) >> 6)
#			urg = bool((flags & 0x0020) >> 5)
#			ack = bool((flags & 0x0010) >> 4)
#			psh = bool((flags & 0x0008) >> 3)
#			rst = bool((flags & 0x0004) >> 2)
#			syn = bool((flags & 0x0002) >> 1)
#			fin = bool((flags & 0x0001))
#			print("TCP flags {flags}".format(flags=hex(flags)))
#	
#			if syn:
#				# Swap source and destination address.
#				ippacket[12:16], ippacket[16:20] = ippacket[16:20], ippacket[12:16]
#				# respond with RST & ACK
#				ippacket[iphdr:][13:14] = chr(0x14)
#				# ACK the SEQ
#				newack = seqno+1
#				ippacket[iphdr:][8:12] = chr((newack & 0xFF000000)>>24),chr((newack & 0xFF0000)>>16),chr((newack & 0xFF00)>>8),chr((newack & 0xFF))
#				# fake the SEQ
#				ippacket[iphdr:][4:8] = chr(0),chr(0),chr(0),chr(1)
#				# TODO: compute new checksum
#				do_write = True
#	
#		else:
#			print("IP: unknown protocol {prot}".format(prot=hex(protocol)))
#	else:
#		print("Unknown / not an IP packet")
#
#	#for x in ippacket:
#	#	print(phex(ord(x)))
#	#print
#	for x in myhexdump(ippacket):
#		print(x )
#
#	if do_write:
#		# Write the reply packet into TUN device.
#		os.write(tun.fileno(), ''.join(ippacket))
#	print("")
