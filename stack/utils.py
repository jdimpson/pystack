#!/usr/bin/env python

# Some constants used to ioctl the device file. I got them by a simple C
# program.
TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

try:
    xrange
except NameError:
    xrange = range

dhproc = None
def stop_dhclient():
	if dhproc:
		dhproc.terminate()
		dhproc.kill()

def ipversion(ippacket):
	tmp=ippacket[0:1][0]
	if isinstance(tmp,str):
		tmp=ord(tmp)
	return (tmp & 0xF0) >> 4

def padded_hex(val, bits=None, bytes=1):
	if bits is None: bits = bytes * 8
	hexlen = int(bits / 4)
	return "{0:0{1}x}".format(val,hexlen)
	# 0: first parameter
	# 0 fill with zeroes
	# {1} to a lenght of n characters, n defined by second parameter
	# x hexadecimal number, using lowercase letters for a-f

phex=padded_hex

def hexlify(s,pad=0):
	o = ''
	for b in s:
		if isinstance(b,str):
		    b=ord(b)
		o += phex(b) + ' '
	o += '   ' * pad
	return o

def safeascii(s):
	o=''
	for b in s:
		if isinstance(b,int):
			b=chr(b)
		if ord(b) > 126 or ord(b) < 33:
			o += '.'
		else:
			o+= b
	return o

def hexdump(b, width=16):
	l=0
	hw = int(width / 2)
	while len(b) > width:
		chunk1 = b[0:hw]
		chunk2 = b[hw:width]
		yield phex(l,bytes=4) + "  " + hexlify(chunk1) + " " + hexlify(chunk2) + "  |" + safeascii(chunk1+chunk2) + "|"
		l+=width
		b = b[width:]
	l-=width
	l+=len(b)
	chunk1 = b[0:hw]
	chunk2 = b[hw:]
	if len(chunk1) < hw:
		pad1 = hw - len(chunk1)
		pad2 = hw
	else:
		pad1 = 0
		if len(chunk2) < hw:
			pad2 = hw - len(chunk2)
		else:
			pad2 = 0
	yield phex(l,bytes=4) + "  " + hexlify(chunk1,pad=pad1) + " " + hexlify(chunk2,pad=pad2) + "  |" + safeascii(b) + "|"

# XXX: Everything based on get_bytes() is dumb, since the packet
# buffers are all bytearrays, yet these bad boys work on and/or 
# produce lists of integers...
# IN MY DEFENSE the original impetus was to make the implementation 
# of TCP and IP checksums easier for me to understand
# also python3 bytes have no bitwise operators so uhmmm what?
def get_bytes(buf,startb,endb):
        return [ ord(x) if isinstance(x,str) else x for x in buf[startb:endb] ]

def set_bytes(buf,startb,endb,vals):
        if not isinstance(vals,list):
                vals = [ vals ]
        buf[startb:endb] = [ x for x in vals ]

def chunker(seq,size):
        for pos in xrange(0,len(seq),size):
                yield seq[pos:pos+size]

def bytes2word(bytes):
        o=0
        for b in bytes:
                o=o<<8
                o=o|b
        return o

def ipv4joinaddress(b):
	return '.'.join([str(x) for x in b])
def ethjoinaddress(b):
	return ':'.join([phex(x) for x in b])

def ipv4splitaddress(s):
	return [ int(x) for x in s.split('.') ]

def ethsplitaddress(s):
	return [ int(x,base=16) for x in s.split(':') ]

def ints2bytes(i):
	o = []
	for x in i:
		b = x.to_bytes(length=1, byteorder='big')
		o.append(b)
	return o

def bytes2ints(b):
	o = []
	for x in b:
		i = int.from_bytes(x, byteorder='big', signed=False)
		o.append(i)
	return o

###
# Multicast
###


def mcastIPv4toMac(ipaddr,asbytes=False):
	ip = ipv4splitaddress(ipaddr)
	if ip[0]& 0b11110000 != 0b11100000:
		raise RuntimeError("IP Address {} is not a valid multicast address".format(ipaddr))
	mac = [1, 0, 83, ip[1] & 0b01111111, ip[2], ip[3]]
	if asbytes:
		return ints2bytes(mac)
	else:
		return ethjoinaddress(mac)

