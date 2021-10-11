from .utils import get_bytes,set_bytes,chunker,padded_hex as phex,bytes2word
from . import utils

ETHIIMIN = 1536
IPV6TYPE = 0x86dd
IPV4TYPE = 0x0800
VLANTYPE = 0x8100
ARPTYPE  = 0x0806
IPXTYPE  = 0x8137
MPLSUNITYPE   = 0x8847
MPLSMULTITYPE = 0x8848
PPPOEDISCTYPE = 0x8863
PPPOESESSTYPE = 0x8864
EAPTYPE = 0x888E
PTPTYPE = 0x88F7
TTECTRLTYPE  = 0x891D
VLANDBLTYPE  = 0x9100
ARPREQUEST   = 1
ARPREPLY     = 2

###
# MAC Header
###
def PAYLOAD(ethframe):
	et = ethertype(ethframe)
	if et < ETHIIMIN:
		# not an Ethernet II frame
		return 14
	if et == VLANTYPE:
		return 16
	if et == VLANDBLTYPE:
		print("VLAN-in-VLAN not yet handled.")
		return None
	return 14

def ethlen(ethframe):
	return len(ethframe)

def ethertype(ethframe):
	h,l = get_bytes(ethframe,12,14,)
	return (h<<8)|l

def addresses(ethframe):
	return ethsrcaddress(ethframe),ethdstaddress(ethframe)

def ethsrcaddress(ethframe,asbytes=False):
	return getaddress(ethframe,6,12,asbytes=asbytes)

def ethdstaddress(ethframe,asbytes=False):
	return getaddress(ethframe,0,6,asbytes=asbytes)

def getaddress(ethframe,s,e,asbytes=False):
	b = get_bytes(ethframe,s,e)
	if asbytes:
		return b
	return utils.ethjoinaddress(b)

def ethswapaddresses(ethframe):
	ethframe[0:6], ethframe[6:12] = ethframe[6:12], ethframe[0:6]

def dstfilter(mac,ethframe,asbytes=False):
    m=ethdstaddress(ethframe,asbytes=asbytes)

    if mac == m:
        return True
    return False

def makeethIIhdr(dstmac,srcmac,type=IPV4TYPE):
	b = bytearray()
	dstmac = setethaddress(dstmac)
	srcmac = setethaddress(srcmac)
	print(dstmac, srcmac)

def setethaddress(mac):
	#if isinstance(dstmac, bytes):
	if   isinstance(mac, str):
		mac = mac.replace(':','')
		mac = bytearray.fromhex(mac)
	elif isinstance(mac, int):
		mac = bytearray(mac.to_bytes(6, byteorder='big'))

	return mac


###
# ARP
###
def arphtype(arpbuf):
	return bytes2word(get_bytes(arpbuf,0,2))
def arpptype(arpbuf):
	return bytes2word(get_bytes(arpbuf,2,4))
def arphlen(arpbuf):
	return get_bytes(arpbuf,4,5)
def arpplen(arpbuf):
	return get_bytes(arpbuf,5,6)
def arpoperation(arpbuf):
	return bytes2word(get_bytes(arpbuf,6,8))
def arpsendermacaddr(arpbuf):
	return utils.ethjoinaddress(get_bytes(arpbuf,8,14))
def arpsenderipaddr(arpbuf):
	if arpptype(arpbuf) == IPV4TYPE:
		return utils.ipv4joinaddress(get_bytes(arpbuf,14,18))
	else:
		return None
def arptargetmacaddr(arpbuf):
	return utils.ethjoinaddress(get_bytes(arpbuf,18,24))
def arptargetipaddr(arpbuf):
	if arpptype(arpbuf) == IPV4TYPE:
		return utils.ipv4joinaddress(get_bytes(arpbuf,24,28))
	else:
		return None


###
# LLC
###
PID_CDP = 0x2000

def dsap(llcbuf): return get_bytes(llcbuf,0,1)[0]
def ssap(llcbuf): return get_bytes(llcbuf,1,2)[0]
def controlfield(llcbuf): return get_bytes(llcbuf,2,3)[0]
def orgcode(llcbuf): return get_bytes(llcbuf, 3,6)
def pid(llcbuf):  return bytes2word(get_bytes(llcbuf,6,8))
def fmtorgcode(oc): return ':'.join([phex(x) for x in oc])
def LLCPAYLOAD(): return 8

