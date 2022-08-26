from .utils import get_bytes,set_bytes,chunker,padded_hex as phex,bytes2word,word2bytes
from . import utils

# breaks my self-imposed rules, but needed for ARP processing
from .ipv4 import ipv4address_asbytes

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
ARPETHTYPE   = 1
ARP_PROBE_WAIT          =  1 # second   (initial random delay)
ARP_PROBE_NUM           =  3 #          (number of probe packets)
ARP_PROBE_MIN           =  1 # second   (minimum delay until repeated probe)
ARP_PROBE_MAX           =  2 # seconds  (maximum delay until repeated probe)
ARP_ANNOUNCE_WAIT       =  2 # seconds  (delay before announcing)
ARP_ANNOUNCE_NUM        =  2 #          (number of Announcement packets)
ARP_ANNOUNCE_INTERVAL   =  2 # seconds  (time between Announcement packets)
ARP_MAX_CONFLICTS       = 10 #          (max conflicts before rate-limiting)
ARP_RATE_LIMIT_INTERVAL = 60 # seconds  (delay between successive attempts)
ARP_DEFEND_INTERVAL     = 10 # seconds  (minimum interval between defensive ARPs)

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

def swapmacs(ethframe):
	ethframe[0:6], ethframe[6:12] = ethframe[6:12], ethframe[0:6]

def set_srcmac(ethframe,mac):
	mac = ethaddress_asints(mac)
	utils.set_bytes(ethframe,6,12,mac)

def dstfilter(mac,ethframe,asbytes=False):
	if isinstance(mac,str):
		mac = ethaddress_asints(mac)
	m=ethdstaddress(ethframe,asbytes=asbytes)

	if mac == m:
		return True
	return False

def srcfilter(mac,ethframe,asbytes=False):
	if isinstance(mac,str):
		mac = ethaddress_asints(mac)
	m=ethsrcaddress(ethframe,asbytes=asbytes)

	if mac == m:
		return True
	return False

def makeethIIhdr(dstmac,srcmac,typ=IPV4TYPE):
	dstmac = ethaddress_asbytes(dstmac)
	srcmac = ethaddress_asbytes(srcmac)
	return dstmac + srcmac + bytearray(typ.to_bytes(2,byteorder='big'))

def ethaddress_asints(mac):
	if   isinstance(mac, str):
		#mac = mac.replace(':','')
		mac = mac.split(':')
		mac = [int(x,base=16) for x in mac]
	if len(mac) != 6:
		raise RuntimeError("six ints required, {} is {}".format(mac,len(mac)))
	return mac

def ethaddress_asbytes(mac):
	if   isinstance(mac, str):
		mac = mac.replace(':','')
		mac = bytearray.fromhex(mac)
	elif isinstance(mac, int):
		mac = bytearray(mac.to_bytes(6, byteorder='big'))

	if not isinstance(mac, (bytearray, bytes)):
		raise RuntimeError("bytes or bytearray required, {} is {}".format(mac,type(mac)))
	if len(mac) != 6:
		raise RuntimeError("six bytes required, {} is {}".format(mac,len(mac)))
	return mac

crc32table = [
     0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
     0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
     0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
     0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
     0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
     0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
     0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
     0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
     0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
     0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
     0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
     0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
     0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
     0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
     0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
     0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
     0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
     0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
     0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
     0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
     0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
     0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
     0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
     0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
     0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
     0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
     0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
     0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
     0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
     0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
     0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
     0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
     0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
     0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
     0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
     0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
     0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
     0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
     0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
     0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
     0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
     0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
     0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
     0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
     0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
     0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
     0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
     0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
     0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
     0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
     0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
     0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
     0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
     0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
     0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
     0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
     0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
     0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
     0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
     0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
     0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
     0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
     0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
     0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
]

# Raw ethernet sockets apparently still perform the CRC calculation, 
# so this code is unverified.
def CRC32(data):
	crc32 = 0xFFFFFFFF

	for i in range(len(data)):
		lookup = (crc32 ^ data[i]) & 0xff
		crc32 = (crc32 >> 8) ^ crc32table[lookup]

	# Finalize the CRC-32 value by inverting all the bits
	crc32 ^= 0xFFFFFFFF
	return crc32

###
# ARP
###
# https://www.rfc-editor.org/rfc/rfc826
# https://www.rfc-editor.org/rfc/rfc3927
# https://www.rfc-editor.org/rfc/rfc5227
def makearpbuf(sha, spa, tha, tpa, oper=ARPREQUEST, htype=ARPETHTYPE, ptype=IPV4TYPE):
	sha = ethaddress_asbytes(sha)
	spa = ipv4address_asbytes(spa)
	tha = ethaddress_asbytes(tha)
	tpa = ipv4address_asbytes(tpa)

	hlen = len(sha).to_bytes(1, byteorder='big')
	plen = len(spa).to_bytes(1, byteorder='big')

	htype = bytearray(htype.to_bytes(2, byteorder='big'))
	ptype = bytearray(ptype.to_bytes(2, byteorder='big'))
	oper = bytearray(oper.to_bytes(2, byteorder='big'))
	
	return htype+ptype+hlen+plen+oper+sha+spa+tha+tpa

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
def set_arpoperation(arpbuf,opera):
	# all three of these work, need to decide what to standardize on. Probably native python .to_bytes()
	#op = [(opera & 0xFF00)>>8,(opera & 0x00FF)]
	#op = word2bytes(opera)
	op = opera.to_bytes(2,byteorder='big')
	set_bytes(arpbuf, 6,8, op)
def arpsendermacaddr(arpbuf):
	return utils.ethjoinaddress(get_bytes(arpbuf,8,14))
def arpsenderipaddr(arpbuf):
	if arpptype(arpbuf) == IPV4TYPE:
		return utils.ipv4joinaddress(get_bytes(arpbuf,14,18))
	else:
		return None
def arpswapsendertarget(arpbuf):
	arpbuf[8:14], arpbuf[14:18], arpbuf[18:24], arpbuf[24:] = arpbuf[18:24], arpbuf[24:], arpbuf[8:14], arpbuf[14:18]
def arptargetmacaddr(arpbuf):
	return utils.ethjoinaddress(get_bytes(arpbuf,18,24))
def set_arptargetmacaddr(arpbuf, macaddr):
	set_bytes(arpbuf, 18,24, macaddr)
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

