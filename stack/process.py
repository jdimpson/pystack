#!/usr/bin/env python

import sys,os
from . import utils
from . import eth
from . import ipv6
from . import ipv4

class IgnorePacket(Exception):
	pass

def report(layer, info):
	return [ "{}:{}".format(layer,i) for i in info ]

class packetEngineBase(object):
	def __init__(self, ttl=8, myipv4addr=None, mymacaddr=None, mcastipv4s=[]):
		self.ttl=ttl
		self.myipv4addrs = [ ]
		self.mymacaddrs  = [ ]
		if mymacaddr is not None or myipv4addr is not None:
			self.myipv4addrs.append(myipv4addr)
			self.mymacaddrs.append(mymacaddr)
		self.mcastips  = mcastipv4s
		self.mcastmacs = [ utils.mcastIPv4toMac(x) for x in mcastipv4s ]

	def processEth(self, frame):
		return ["Eth frame not processed"],None
	def processVLAN(self, frame):
		return ["VLAN frame not processed"],None
	def processIP(self, frame):
		return ["IPvX packet not processed"],None
	def processIPv4(self, frame):
		return ["IPv4 packet not processed"],None
	def processIPv6(self, frame):
		return ["IPv6 packet not processed"],None
	def processARP(self, frame, respond=False):
		return ["ARP packet not processed"],None
	def processLLC(self, frame, respond=False):
		return ["LLC frame not processed"],None
	def processICMPv4(self, frame, respond=False):
		return ["ICMPv4 payload not processed"],None
	def processTCP(self, frame, respond=False):
		return ["TCP payload not processed"],None
	def processUDP(self, frame, respond=False):
		return ["UDP payload not processed"],None

class packetEngine(packetEngineBase):

	def processEth(self, ethframe):
		info = []
		info.append("RECEIVED ETH FRAME")
		info.append("Ethernet frame (assumed)")

		srcmac,dstmac = eth.addresses(ethframe)
		info.append("MAC addresses {src} => {dst}".format(src=srcmac,dst=dstmac))
		ethertype = eth.ethertype(ethframe)
		o=None
		if ethertype < eth.ETHIIMIN: 
			info.append("LLC (Non-Ethernet II) frame")
			llcframe = ethframe[eth.PAYLOAD(ethframe):]
			llclength = ethertype
			llcframe = llcframe[:llclength]
			i,o = self.processLLC(llcframe)
			for j in i: info.append(j)
		elif ethertype == eth.IPV6TYPE:
			info.append("IPv6 packet")
			ippacket = ethframe[eth.PAYLOAD(ethframe):]
			i,o = self.processIPv6(ippacket)
			for j in i: info.append(j)
		elif ethertype == eth.IPV4TYPE:
			info.append("IPv4 packet")
			ippacket = ethframe[eth.PAYLOAD(ethframe):]
			i,o = self.processIPv4(ippacket)
			for j in i: info.append(j)
		elif ethertype == eth.VLANTYPE:
			info.append("VLAN header")
			i,o = self.processVLAN(ethframe)
			for j in i: info.append(j)
		elif ethertype == eth.ARPTYPE:
			info.append("ARP packet")
			arppacket = ethframe[eth.PAYLOAD(ethframe):]
			i,o = self.processARP(arppacket, respond=True)
			for j in i: info.append(j)
		else:
			info.append("Unknown ethertype {ty}".format(ty=hex(ethertype)))

		if o is not None:
			ethframe[eth.PAYLOAD(ethframe):] = o
			info.append("Swapping src and dst macs")
			eth.swapmacs(ethframe)
			info.append("overwriting src mac with {}".format(self.mymacaddrs[0]))
			eth.set_srcmac(ethframe, utils.ethsplitaddress(self.mymacaddrs[0]))

			o = ethframe
		return report("ETH", info), o

	def processLLC(self, llcframe, respond=False):
		info = []
		info.append("RECEIVED LLC FRAME")
		#for x in utils.hexdump(llcframe): info.append(x)
		dsap = eth.dsap(llcframe)
		ssap = eth.ssap(llcframe)
		cf   = eth.controlfield(llcframe)
		oc   = eth.orgcode(llcframe)
		pid  = eth.pid(llcframe)

		oc = eth.fmtorgcode(oc)
		if pid == eth.PID_CDP:
			pid = "Cisco Discovery Protocol"

		info.append("dsap {}".format(dsap))
		info.append("ssap {}".format(ssap))
		info.append("cf   {}".format(cf))
		info.append("oc   {}".format(oc))
		info.append("pid  {}".format(pid))

		pay = llcframe[eth.LLCPAYLOAD():]
		info.append("LLC PAYLOAD")
		for x in utils.hexdump(pay): info.append(x)

		return report("LLC", info), None

	def processARP(self,arpbuf, respond=False):
		info = []
		o = None
		info.append("RECEIVED ARP PACKET")
		# TODO: ARP stuffing to set my IP (not actually something you do with ARP), Reply to all ARPs in the 169 autoip range to f* with it.
	
		htype = eth.arphtype(arpbuf)
		ptype = eth.arpptype(arpbuf)
		hlen  = eth.arphlen(arpbuf)
		plen  = eth.arpplen(arpbuf)
		opera = eth.arpoperation(arpbuf)
		smac  = eth.arpsendermacaddr(arpbuf)
		sip   = eth.arpsenderipaddr(arpbuf)
		tmac  = eth.arptargetmacaddr(arpbuf)
		tip   = eth.arptargetipaddr(arpbuf)

		if opera == eth.ARPREQUEST:
			opera = "request"
		elif opera == eth.ARPREPLY:
			opera = "reply"

		info.append("htype {}".format(htype))
		info.append("ptype {}".format(ptype))
		info.append("hlen  {} plen {}".format(hlen,plen))
		info.append("opera {}".format(opera))
		info.append("smac  {}".format(smac))
		info.append("sip   {}".format(sip))
		info.append("tmac  {}".format(tmac))
		info.append("tip   {}".format(tip))

		if opera == "request" and tip in self.myipv4addrs:
			info.append("ARP is for my ip {}".format(tip))
			if respond:
				eth.set_arpoperation(arpbuf, eth.ARPREPLY)
				i = self.myipv4addrs.index(tip)
				m = self.mymacaddrs[i]
				if m is None:
					info.append("Cannot reply because have no mac address for {}".format(tip))
				else:
					info.append("Making reply")
					eth.set_arptargetmacaddr(arpbuf,utils.ethsplitaddress(m))
					eth.arpswapsendertarget(arpbuf)
					o = arpbuf

		return report("ARP", info), o

	# This is needed as an entry point on TUN interfaces which handle either kind of IP packet, but not Ethernet frames
	def processIP(self, ippacket):
		info = []
		o = None
		ipver = utils.ipversion(ippacket)

		if   ipver == ipv4.VERSION:
			return self.processIPv4(ippacket)
		elif ipver == ipv6.VERSION:
			return self.processIPv6(ippacket)
		else:
			info.append("Unknown / not an IPv4 packet: {}".format(ipver))
			return report("IPvX", info), None

	def processIPv4(self, ippacket):
		info = []
		o = None
		ipver = utils.ipversion(ippacket)

		if ipver != ipv4.VERSION:
			info.append("Unknown / not an IPv4 packet")
			return report("IPv4", info), None

		tome = False

		info.append("RECEIVED IPv4 PACKET")
		protocol = ipv4.protocol(ippacket)
		srcaddr,dstaddr = ipv4.addresses(ippacket)
		info.append("{s} => {d}".format(s=srcaddr,d=dstaddr))
		ttl = ipv4.ipttl(ippacket)
		info.append("IP TTL {}".format(ttl))

		if dstaddr in self.myipv4addrs:
			info.append("Packet is unicast addressed to me! {}".format(dstaddr))
			tome = True

		if protocol == ipv4.ICMPTYPE:
			i, o = self.processICMPv4(ippacket, respond=tome)
			for j in i: info.append(j)

		elif protocol == ipv4.TCPTYPE:
			i, o = self.processTCP(ippacket, respond=tome)
			for j in i: info.append(j)

		elif protocol == ipv4.UDPTYPE:
			i, o = self.processUDP(ippacket, respond=tome)
			for j in i: info.append(j)

		else:
			info.append("IPv4 unknown protocol {prot}".format(prot=hex(protocol)))

		if o is not None:
			# Set TTL to my default (which should be based on how robust you think this code is :)
			ipv4.set_ipttl(ippacket,self.ttl)

			# Since we are reusing this packet, then if we only swap IP 
			# addresses, we could just reuse previous checksum. But not if
			# we change, say, the TTL.
			s = ipv4.ipcomputechecksum(ippacket)
			ipv4.set_ipchecksum(ippacket,s)

		return report("IPv4", info), o

	def processICMPv4(self,ippacket, respond=False):
		info = []
		o = None
		type,code,name = ipv4.icmpidentify(ippacket)
		info.append("ICMPv4 {n} type {t} code {c}".format(n=name,t=type,c=code))
		if type == ipv4.ICMPECHOREQUEST:
			# Modify it to an ICMP Echo Reply packet.
			if code != 0x0:
				info.append("ICMPv4 code is {code}, expected 0x0, ignoring descrepency".format(hex(code)))

			if respond:
				info.append("Responding to ECHO REQUEST with ECHO RESPONSE")
				ipv4.icmpechoresponse(ippacket)
				o = ippacket
		else:
			info.append("Don't currently handle ICMP type {}".format(type))

		return report("ICMPv4", info), o

	def processTCP(self, ippacket, respond=False):
		info = []
		o = None
		srcport, dstport = ipv4.tcpports(ippacket)
		info.append("TCP ports {src} => {dst}".format(src=srcport,dst=dstport))

		seqno,ackno = ipv4.tcpseqackno(ippacket)
		info.append("TCP seqno {seq}".format(seq=hex(seqno)))
		info.append("TCP ackno {ack}".format(ack=hex(ackno)))

		hdrlen = ipv4.tcphdrlen(ippacket)
		info.append("TCP hdrlen {hdr}".format(hdr=hdrlen))

		flags = ipv4.tcpflags(ippacket)
		info.append("TCP flags {flags}".format(flags=hex(flags)))

		f = ipv4.tcpextractflags(flags)
		#info.append("TCP flags {s}".format(s=str(f)))
		if f['syn']:
			info.append("Responding to TCP SYN with TCP RST")
			ipv4.tcpsynrst(ippacket)
			return report("TCP", info), ippacket
		else:
			return report("TCP", info), None

	def processUDP(self, ippacket, respond=False):
		info = []
		o = None
		srcport, dstport = ipv4.udpports(ippacket)
		info.append("UDP ports {src} => {dst}".format(src=srcport,dst=dstport))

		seglen = ipv4.udpseglen(ippacket)
		info.append("UDP segment length {len}".format(len=seglen))

		if dstport == 67 and srcport == 68:
			info.append("DHCP client")
			dhcp = ipv4.dhcpparse(ippacket)
			info.append("DHCP message type {}".format(dhcp['msgtype']))
			info.append("DHCP OP    {}".format(dhcp['op']))
			info.append("DHCP HTYPE {}".format(dhcp['htype']))
			info.append("DHCP HLEN  {}".format(dhcp['hlen']))
			info.append("DHCP HOPS  {}".format(dhcp['hops']))
			info.append("DHCP XID   {}".format(hex(dhcp['xid'])))
			info.append("DHCP flags {}".format(hex(dhcp['flags'])))
			info.append("Client IP Address  {}".format(dhcp['ciaddr']))
			info.append("Your IP Address    {}".format(dhcp['yiaddr']))
			info.append("Server IP Address  {}".format(dhcp['siaddr']))
			info.append("Relay IP Address   {}".format(dhcp['giaddr']))
			info.append("Client MAC Address {}".format(dhcp['chaddr']))
			info.append("Server Name  {}".format(dhcp['sname']))
			info.append("Magic Cookie {}".format(dhcp['cookie']))

			info.append("DHCP Options")
			for k in dhcp['options']:
				v = dhcp['options'][k]
				info.append("{k}\t{v}".format(k=k,v=v))
		elif dstport == 514:
			#info.append("SYSLOG message")
			f,l = ipv4.faclev(ippacket)
			mess = ipv4.message(ippacket)
			info.append("SYSLOG {}.{} {}".format(f,l,mess))
		# TODO: else: icmp response
		return report("UDP", info), None

def processIPv6(ippacket,myttl=8):
	info = []
	o = None

	ipver = utils.ipversion(ippacket)
	output = False

	if ipver == ipv6.VERSION:
		info.append("RECEIVED IPv6 PACKET")
		length  = ipv6.length(ippacket)
		nexthdr = ipv6.nexthdr(ippacket)
		info.append("length {}, nexthdr {}".format(length, nexthdr))
		if nexthdr == ipv6.ICMPTYPE:
			# ICMPv6
			type,code,name=ipv6.icmpidentify(ippacket)
			body = ipv6.icmpbody(ippacket)
			info.append("ICMPv6 {n} type {t} code {c}".format(n=name,t=type,c=code))
		if nexthdr == ipv6.UDPTYPE:
			info.append("UDP message")
		else:
			info.append("IPv6 unhandled next header value {nh}".format(nh=hex(nexthdr)))
	else:
		info.append("Unknown / not an IPv6 packet")

	return report("IPv6", info), o


