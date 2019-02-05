from .utils import get_bytes,set_bytes,chunker,padded_hex as phex,bytes2word
from . import utils

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
	if et < 1536:
		# not an Ethernet II frame
		print("Non-Ethernet II frames not yet handled.")
		return None
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

