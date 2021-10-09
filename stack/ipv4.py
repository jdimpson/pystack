from .utils import get_bytes,set_bytes,chunker,bytes2word,padded_hex as phex
from . import utils

VERSION=4
ICMPTYPE=0x1
TCPTYPE=0x6
UDPTYPE=0x11
ICMPECHOREQUEST=0x8
ICMPECHOREPLY=0x0
ICMPDESTUNREACH=0x3
ICMPTIMEEXCEEDED=0xb

###
# IP Header
###
def PAYLOAD(ippacket):
	ihl = ipihl(ippacket)
	return ihl * 4

def ipihl(ippacket):
	return get_bytes(ippacket,0,1)[0] & 0xF

def protocol(ippacket):
	return get_bytes(ippacket,9,10)[0]

def addresses(ippacket):
	return ipsrcaddress(ippacket),ipdstaddress(ippacket)

def ipsrcaddress(ippacket,asbytes=False):
	return getaddress(ippacket,12,16,asbytes=asbytes)

def ipdstaddress(ippacket,asbytes=False):
	return getaddress(ippacket,16,20,asbytes=asbytes)

def getaddress(ippacket,s,e,asbytes=False):
	b = get_bytes(ippacket,s,e)
	if asbytes:
		return b
	return utils.ipv4joinaddress(b)

def ipswapaddresses(ippacket):
	ippacket[12:16], ippacket[16:20] = ippacket[16:20], ippacket[12:16]

def ipchecksum(ippacket):
	h,l = get_bytes(ippacket,10,12)
	return (h<<8)|l

def set_ipchecksum(ippacket,sum):
	ck = [(sum & 0xFF00)>>8,(sum & 0x00FF)]
	set_bytes(ippacket,10,12,ck)

def ipcomputechecksum(ippacket):
	# covers only the IP header itself
	sum = 0

	# Requires checksum field is set to 0x00
	set_ipchecksum(ippacket,0)

	# covers options, if present, but I'm not sure if it should
	for chunk in chunker(ippacket[0:PAYLOAD(ippacket)] , 2):
		w = bytes2word(chunk)
		sum += w

	# fold in the carry
	carry = (sum & 0xF0000)>>16
	sum   =  sum & 0xFFFF
	sum  += carry

	# one's comp
	sum = 0xFFFF - sum

	return sum

def ipttl(ippacket):
	return get_bytes(ippacket,8,9)[0]

def set_ipttl(ippacket,ttl):
	set_bytes(ippacket,8,9,[ttl])

###
# ICMP
###
def icmptype(ippacket):
	return get_bytes(ippacket,PAYLOAD(ippacket)+0,PAYLOAD(ippacket)+1)[0]
def icmpcode(ippacket):
	return get_bytes(ippacket,PAYLOAD(ippacket)+1,PAYLOAD(ippacket)+2)[0]

def icmpbody(ippacket):
	pass

def icmpidentify(ippacket):
	type = icmptype(ippacket)
	code = icmpcode(ippacket)
	name = "unknown type/code pair"

	if type == ICMPECHOREQUEST and code == 0:
		name = "Echo Request"
	elif type == ICMPECHOREPLY and code == 0:
		name = "Echo Reply"
	elif type == ICMPDESTUNREACH:
		name = "Destination Unreachable"
		if code == 0:
			 name += ": Network Unreachable"
		elif code == 1:
			 name += ": Host Unreachable"
		elif code == 2:
			 name += ": Protocol Unreachable"
		elif code == 3:
			 name += ": Port Unreachable"
		elif code == 4:
			 name += ": Fragmentation Required but DF set"
		elif code == 5:
			 name += ": Source Route Failed (what were you thinking?)"
		elif code == 6:
			 name += ": Network Unknown"
		elif code == 7:
			 name += ": Host Unknown"
		elif code == 8:
			 name += ": Source Host Isolated(?)"
		elif code == 9:
			 name += ": Network Administratively Prohibited (firewalled!)"
		elif code == 10:
			 name += ": Host Administratively Prohibited (firewalled!)"
		elif code == 11:
			 name += ": Network Unreachable for packet's ToS value"
		elif code == 12:
			 name += ": Host Unreachable for packet's ToS value"
		elif code == 13:
			 name += ": Communicated Administratively Prohibited(?)"
		elif code == 14:
			 name += ": Host Precedence Violation (ToS value)"
		elif code == 15:
			 name += ": Precedence Cutoff in Effect (ToS value)"
		else: 
			name += ": unknown code {}".format(code)
	elif type == ICMPTIMEEXCEEDED:
		name = "Time Exceeded"
		if code == 0:
			name += ": TTL Expired in Transit"
		elif code == 1:
			name += ": Fragment Reassembly Time Exceeded"
		else:
			name += ": unknown code {}".format(code)

	return type,code,name	

def icmpchecksum(ippacket):
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+2,PAYLOAD(ippacket)+4)
	return (h<<8)|l

def set_icmpchecksum(ippacket,sum):
	ck = [(sum & 0xFF00)>>8,(sum & 0x00FF)]
	set_bytes(ippacket,PAYLOAD(ippacket)+2,PAYLOAD(ippacket)+4,ck)

def icmpcomputechecksum(ippacket):
	# covers only the ICMP header itself
	sum = 0

	# Requires checksum field is set to 0x00
	set_icmpchecksum(ippacket,0)

	# from start of icmp header until end of IPv4 payload
	# XXX: this breaks if ippacket has an ethernet footer... does it?
	for chunk in chunker(ippacket[PAYLOAD(ippacket):], 2):
		w = bytes2word(chunk)
		sum += w

	# fold in the carry
	carry = (sum & 0xF0000)>>16
	sum   =  sum & 0xFFFF
	sum  += carry

	# one's comp
	sum = 0xFFFF - sum

	return sum

def icmpechoresponse(ippacket):
	# Modify Echo Request to an ICMP Echo Reply packet.

	# Swap source and destination address.
	#ippacket[12:16], ippacket[16:20] = ippacket[16:20], ippacket[12:16]
	ipswapaddresses(ippacket)
	
	# Change ICMP type code to Echo Reply (0).
	ippacket[20] = 0

	sum = icmpcomputechecksum(ippacket)

	set_icmpchecksum(ippacket,sum)
	return

	# Clear original ICMP Checksum field.
	ippacket[22:24] = chr(0), chr(0)

	# Calculate new checksum.
	checksum = 0
	# for every 16-bit of the ICMP payload:
	for i in range(20, len(ippacket), 2):
		half_word = (ord(ippacket[i]) << 8) + ord(ippacket[i+1])
		checksum += half_word
	# Get one's complement of the checksum.
	checksum = ~(checksum + 4) & 0xffff
	# Put the new checksum back into the packet.
	ippacket[22] = chr(checksum >> 8)
	ippacket[23] = chr(checksum & ((1 << 8) -1))

###
# UDP
###
def UDP(ippacket):
	return PAYLOAD(ippacket) + 8

def udpports(ippacket):
	# ports
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+0,PAYLOAD(ippacket)+2)
	srcport = h<<8 | l
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+2,PAYLOAD(ippacket)+4)
	dstport = h<<8 | l
	return srcport, dstport

def udpswapports(ippacket):
	ippacket[PAYLOAD(ippacket)+0:PAYLOAD(ippacket)+2],ippacket[PAYLOAD(ippacket)+2:PAYLOAD(ippacket)+4] = ippacket[PAYLOAD(ippacket)+2:PAYLOAD(ippacket)+4],ippacket[PAYLOAD(ippacket)+0:PAYLOAD(ippacket)+2]

def udpseglen(ippacket):
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+4,PAYLOAD(ippacket)+6)
	return (h << 8) | l

def set_udpchecksum(ippacket,sum):
	ck = [(sum & 0xFF00)>>8,(sum & 0x00FF)]
	set_bytes(ippacket,PAYLOAD(ippacket)+6,PAYLOAD(ippacket)+8,ck)

def udpchecksum(ippacket):
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+6,PAYLOAD(ippacket)+8)
	return (h << 8) | l

def udpcomputechecksum(ippacket):
	return tcpcomputechecksum(ippacket)


###
# TCP
###
def tcpports(ippacket):
	# ports
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+0,PAYLOAD(ippacket)+2)
	srcport = h<<8 | l
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+2,PAYLOAD(ippacket)+4)
	dstport = h<<8 | l
	return srcport, dstport

def tcpswapports(ippacket):
	ippacket[PAYLOAD(ippacket)+0:PAYLOAD(ippacket)+2],ippacket[PAYLOAD(ippacket)+2:PAYLOAD(ippacket)+4] = ippacket[PAYLOAD(ippacket)+2:PAYLOAD(ippacket)+4],ippacket[PAYLOAD(ippacket)+0:PAYLOAD(ippacket)+2]

def tcpseqackno(ippacket):
	# sequence and ACK
	return tcpseqno(ippacket),tcpackno(ippacket)

def tcpseqno(ippacket):
	h,m,f,l = get_bytes(ippacket,PAYLOAD(ippacket)+4,PAYLOAD(ippacket)+8)
	seqno = (h<<24)|(m<<16)|(f<<8)|l
	return seqno

def set_tcpseqno(ippacket,seqno):
	sq = [ (seqno & 0xFF000000)>>24, (seqno & 0x00FF0000)>>16, (seqno & 0x0000FF00)>>8,(seqno & 0x000000FF) ]
	set_bytes(ippacket,PAYLOAD(ippacket)+4,PAYLOAD(ippacket)+8,sq)

def tcpackno(ippacket):
	h,m,f,l = get_bytes(ippacket,PAYLOAD(ippacket)+8,PAYLOAD(ippacket)+12)
	ackno = (h<<24)|(m<<16)|(f<<8)|l
	return ackno

def set_tcpackno(ippacket,ackno):
	ak = [ (ackno & 0xFF000000)>>24, (ackno & 0x00FF0000)>>16, (ackno & 0x0000FF00)>>8,(ackno & 0x000000FF) ]
	set_bytes(ippacket,PAYLOAD(ippacket)+8,PAYLOAD(ippacket)+12,ak)

def tcpflags(ippacket):
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+12,PAYLOAD(ippacket)+14)
	flags  = (h & 0x01) << 8 | l
	return flags

def tcphdrlen(ippacket):
	h = get_bytes(ippacket,PAYLOAD(ippacket)+12,PAYLOAD(ippacket)+13)[0]
	len = (h & 0xf0) >> 4
	len = len * 4 # 32-bit words to 8-bit bytes
	return len

def set_tcphdrlen(ippacket,len):
	if len > 60:
		print("WARNING: Length of TCP header can't be greater than 60! Given len %s" % len)
	if len % 4 > 0:
		print("WARNING: Length of TCP header must be multiple of 4! Given len %s" % len)
	lwords = int(len / 4)
	ns = get_bytes(ippacket,PAYLOAD(ippacket)+12,PAYLOAD(ippacket)+13)[0]
	ns = ns & 0x01
	lwords = (lwords << 4) | ns
	set_bytes(ippacket,PAYLOAD(ippacket)+12,PAYLOAD(ippacket)+13,[lwords])

def tcpextractflags(flags):
	f={}
	f['ns']  = bool((flags & 0x0100) >> 8)
	f['cwr'] = bool((flags & 0x0080) >> 7)
	f['ece'] = bool((flags & 0x0040) >> 6)
	f['urg'] = bool((flags & 0x0020) >> 5)
	f['ack'] = bool((flags & 0x0010) >> 4)
	f['psh'] = bool((flags & 0x0008) >> 3)
	f['rst'] = bool((flags & 0x0004) >> 2)
	f['syn'] = bool((flags & 0x0002) >> 1)
	f['fin'] = bool((flags & 0x0001))
	return f

def set_tcpwindowsize(ippacket,size):
	sz = [ (size & 0xFF00) >> 8, (size & 0x00FF) ]
	set_bytes(ippacket,PAYLOAD(ippacket)+14,PAYLOAD(ippacket)+16, sz)

def set_tcpchecksum(ippacket,sum):
	ck = [(sum & 0xFF00)>>8,(sum & 0x00FF)]
	set_bytes(ippacket,PAYLOAD(ippacket)+16,PAYLOAD(ippacket)+18,ck)

def tcpchecksum(ippacket):
	h,l = get_bytes(ippacket,PAYLOAD(ippacket)+16,PAYLOAD(ippacket)+18)
	return (h << 8) | l

def tcpcomputechecksum(ippacket):
	sum=0

	# pseudo header
	sl = len(ippacket[PAYLOAD(ippacket):])
	seglen = [(sl&0xFF00)>>8,(sl&0x00FF)]
	for chunk in chunker(ipsrcaddress(ippacket,asbytes=True) + ipdstaddress(ippacket,asbytes=True) + [0x0, protocol(ippacket), seglen[0], seglen[1]], 2):
		w = bytes2word(chunk)
		sum += w

	# TCP segment(header and data)
	for chunk in chunker(ippacket[PAYLOAD(ippacket):], 2):
		w = bytes2word(chunk)
		sum += w

	# fold in the carry
	carry = (sum & 0xF0000)>>16
	sum   =  sum & 0xFFFF
	sum  += carry

	# one's comp
	sum = 0xFFFF - sum

	return sum

def tcpsynrst(ippacket):
	seqno,ackno = tcpseqackno(ippacket)
	# Swap source and destination address.
	ipswapaddresses(ippacket)

	# Likewise swap ports
	tcpswapports(ippacket)

	# respond with RST & ACK flag
	set_bytes(ippacket,PAYLOAD(ippacket)+13,PAYLOAD(ippacket)+14,[0x14])

	# ACK the SEQ
	newack = seqno+1
	set_tcpackno(ippacket,newack)

	# make new SEQ
	set_tcpseqno(ippacket,0)

	# set window scale size to 0
	set_tcpwindowsize(ippacket,0)

	# check for and remove options; set header length to 20
	hdrlen = tcphdrlen(ippacket)
	if hdrlen > 20:
		set_tcphdrlen(ippacket,20)
		overhang = hdrlen - 20
		nullpad = [0] * overhang
		set_bytes(ippacket,PAYLOAD(ippacket)+20,PAYLOAD(ippacket)+hdrlen, nullpad)
	
	set_tcpchecksum(ippacket,0)
	cksum = tcpcomputechecksum(ippacket)
	set_tcpchecksum(ippacket,cksum)

###
# DHCP
###

def dhcpparse(ippacket):
	op    = get_bytes(ippacket,UDP(ippacket)+0,UDP(ippacket)+1)[0]
	htype = get_bytes(ippacket,UDP(ippacket)+1,UDP(ippacket)+2)[0]
	hlen  = get_bytes(ippacket,UDP(ippacket)+2,UDP(ippacket)+3)[0]
	hops  = get_bytes(ippacket,UDP(ippacket)+3,UDP(ippacket)+4)[0]

	o,t,r,f = get_bytes(ippacket,UDP(ippacket)+4,UDP(ippacket)+8)
	xid     = (o << 24)|(t << 16)|(r << 8)|f

	h,l  = get_bytes(ippacket,UDP(ippacket)+8,UDP(ippacket)+10)
	secs = (h << 8)| l
	h,l   = get_bytes(ippacket,UDP(ippacket)+10,UDP(ippacket)+12)
	flags = (h << 8)| l

	ciaddr  = getaddress(ippacket,UDP(ippacket)+12,UDP(ippacket)+16)
	yiaddr  = getaddress(ippacket,UDP(ippacket)+16,UDP(ippacket)+20)
	siaddr  = getaddress(ippacket,UDP(ippacket)+20,UDP(ippacket)+24)
	giaddr  = getaddress(ippacket,UDP(ippacket)+24,UDP(ippacket)+28)

	if hlen > 16: hlen = 16
	#chaddr  = ':'.join([phex(x) for x in get_bytes(ippacket,UDP(ippacket)+28,UDP(ippacket)+28+hlen)])
	chaddr  = utils.ethjoinaddress(get_bytes(ippacket,UDP(ippacket)+28,UDP(ippacket)+28+hlen))
	chpad   = ''.join([phex(x) for x in get_bytes(ippacket,UDP(ippacket)+28+hlen,UDP(ippacket)+44)])

	sname   = ''.join([chr(x) for x in get_bytes(ippacket,UDP(ippacket)+44,UDP(ippacket)+108) if x != 0x0])

	file = ''.join([chr(x) for x in get_bytes(ippacket,UDP(ippacket)+108,UDP(ippacket)+236)])
	cookie = hex(bytes2word(get_bytes(ippacket,UDP(ippacket)+236,UDP(ippacket)+240)))
	opts = dhcpparseoptions(get_bytes(ippacket,UDP(ippacket)+240,len(ippacket)))

	msgtype = opts["Message Type"]

	return {

		'msgtype': msgtype,
		'op':      op,
		'htype':   htype,
		'hlen':    hlen,
		'hops':    hops,
		'xid':     xid,
		'flags':   flags,
		'ciaddr':  ciaddr,
		'yiaddr':  yiaddr,
		'siaddr':  siaddr,
		'giaddr':  giaddr,
		'chaddr':  chaddr,
		'sname':   sname,
		'cookie':  cookie,
		'options': opts,
	}

def dhcpparseoptions(options):
	opts = {}
	while len(options) > 0:
		t = options[0]
		if t == 255:
			break
		l = options[1]
		args = options[2:2+l]
		# DHCP Message Type
		if t == 53:
			t = "Message Type"
			args = args[0]
			args = dhcpmsgtype(args)
		elif t == 12:
			t = "Hostname"
			args = ''.join([chr(x) for x in args])
		elif t == 61:
			t = "Client Identifier"
			hw = args[0]
			mac = ':'.join([phex(x) for x in args[1:]])
			args = "hw({hw}) {mac}".format(hw=hw,mac=mac)
		elif t == 80:
			t = "Rapid Commit"
			args = True
		elif t == 60:
			t = "Vendor Class Identifier"
			args = ''.join([chr(x) for x in args])
		elif t == 116:
			t = "DHCP autoconfiguration"
			args = args[0]
			if args == 1:
				args = "Autoconfigure"
		elif t == 55:
			t = "Parameter request list"
			args = ' '.join([phex(x) for x in args])
		elif t == 57:
			t = "Maximum Message Size"
			args = args[0]
		elif t == 145:
			t = "Forcerenew Nonce Capable"
			args = True
		elif t == 50:
			t = "Specific Address Requested"
			args = "{}.{}.{}.{}".format(*args)
		else:
			t = "DHCP option {}".format(t)

		opts[t] = args
		options = options[2+l:]
	return opts

def dhcpmsgtype(t):
	if t == 1:
		return "Discover"
	elif t == 2:
		return "Offer"
	elif t == 3:
		return "Request"
	elif t == 4:
		return "ACK"
	elif t == 5:
		return "NAK"
	elif t == 6:
		return "Decline"
	elif t == 7:
		return "Release"
	elif t == 8:
		return "Inform"
	else:
		return "Unknown"

def dhcpop(op):
	if op == 1:
		return "BOOTREQUEST"
	elif op == 2:
		return "BOOTREPLY"
	else:
		return "UNKNOWN BOOT OP"
