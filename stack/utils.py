
def ipversion(ippacket):
	return (ord(ippacket[0:1][0]) & 0xF0) >> 4

def padded_hex(val, bits=None, bytes=1):
	if bits is None: bits = bytes * 8
	hexlen = (bits / 4)
	return "{0:0{1}x}".format(val,hexlen)
	# 0: first parameter
	# 0 fill with zeroes
	# {1} to a lenght of n characters, n defined by second parameter
	# x hexadecimal number, using lowercase letters for a-f

phex=padded_hex

def hexlify(s):
	o = ''
	for b in s:
		b=ord(b)
		o += phex(b) + ' '
	return o

def safeascii(s):
	o=''
	for b in s:
		if ord(b) > 126 or ord(b) < 33:
			o += '.'
		else:
			o+= b
	return o

def hexdump(b, width=16):
	if isinstance(b,list):
		b = ''.join(b)
	l=0
	hw = width / 2
	while len(b) > width:
		chunk1 = b[0:hw]
		chunk2 = b[hw:width]
		yield phex(l,bytes=4) + "  " + hexlify(chunk1) + " " + hexlify(chunk2) + "  |" + safeascii(chunk1+chunk2) + "|"
		l+=width
		b = b[width:]
	l-=width
	l+=len(b)
	yield phex(l,bytes=4) + "  " + hexlify(b[0:hw]) + " " + hexlify(b[hw:]) + "  |" + safeascii(b) + "|"


