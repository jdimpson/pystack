

VERSION=4
ICMPTYPE=0x1
TCPTYPE=0x6
ICMPECHOREQUEST=0x8

###
# Util
###
def get_bytes(buf,startb,endb):
	return [ ord(x) for x in buf[startb:endb] ]

def set_bytes(buf,startb,endb,vals):
	if not isinstance(vals,list):
		vals = [ vals ]
	buf[startb:endb] = [ chr(x) for x in vals ]

def chunker(seq,size):
	for pos in xrange(0,len(seq),size):
		yield seq[pos:pos+size]

###
# Header
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
	return '.'.join([str(x) for x in b])

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
	for chunk in chunker( [ord(x) for x in ippacket[0:PAYLOAD(ippacket)]] , 2):
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
	set_ipchecksum(ippacket,0)

	# covers options, if present, but I'm not sure if it should
	for chunk in chunker( [ord(x) for x in ippacket[PAYLOAD(ippacket):PAYLOAD(ippacket)+8]] , 2):
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
	ippacket[20] = chr(0)

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
		print "WARNING: Length of TCP header can't be greater than 60! Given len %s" % len
	if len % 4 > 0:
		print "WARNING: Length of TCP header must be multiple of 4! Given len %s" % len
	lwords = len / 4
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
	return (l << 8) | l

def bytes2word(bytes):
	o=0
	for b in bytes:
		o=o<<8
		o=o|b
	return o

def tcpcomputechecksum(ippacket):
	sum=0

	# pseudo header
	sl = len(ippacket[PAYLOAD(ippacket):])
	seglen = [(sl&0xFF00)>>8,(sl&0x00FF)]
	for chunk in chunker(ipsrcaddress(ippacket,asbytes=True) + ipdstaddress(ippacket,asbytes=True) + [0x0, protocol(ippacket), seglen[0], seglen[1]], 2):
		w = bytes2word(chunk)
		sum += w

	# TCP segment(header and data)
	for chunk in chunker( [ord(x) for x in ippacket[PAYLOAD(ippacket):]] , 2):
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
