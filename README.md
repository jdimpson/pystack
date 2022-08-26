# pystack
## Pure Python 3 Usermode IP Stack

Mostly intended as a learning exercise, to look closely at IPv6 and etc. 
But secretly also hoping to become a useful utility for unusual network tasks, such as supporting network simulations, making userspace bridges and routers, clearing TIME_WAIT entries (like https://github.com/rghose/kill-close-wait-connections/), or an inline deep packet inspector/man-in-the-middler. But for now doesn't really do anything but answer pings. Sometimes.

## Getting Started

### download it, nothing to install now.
	git clone https://github.com/jdimpson/pystack.git
	cd pystack

There are no explicit dependencies, but I'm sure lots of implicit ones.

### crude packet sniffer and decoder using raw sockets as the interface
	sudo ./raw.py

### ICMP ping responder using a TUN device as the interface
	sudo ./tun.py &
	sleep 1
	ping 192.168.7.2

Sets up a tunnel device then will respond to ICMP echo requests

### ICMP ping responder using a TAP device as the interface
	sudo ./tap.py &
	sleep 1
	ping 192.168.7.2

Sets up a tap device then will respond to ICMP echo and ARP requests 

### Send an LLC/loop/ECTP frame over a raw interface
	sudo tcpdump ether proto 0x9000 &
	sleep 5
	sudo ./sendloopraw.py

Doesn't do anything except create a single Ethernet frame with 0x9000 in the EtherType field. 0x9000 is the reserved value for Ethernet Configuration Testing Protocol (ECTP). ECTP isn't in common use, although apparently is the basis for thoe LLC Loop detecting packets you see in Wireshark sometimes. I thought it would be cool to implement more of the ECTP functions. Then I got distracted by shinier things.

See https://aminems.github.io/ctp.html for more information.

### Send gratuitous ARP requests
	sudo tcpdump arp &
	sleep 5
	sudo ./gratuitousarp.py 10.0.0.5 eth0 aa:bb:cc:dd:ee:ff

You know, gratuitous ARP.

### Simple stupid user mode end point
	sudo ./usermodeendpoint.py 10.0.0.5 eth0 aa:bb:cc:dd:ee:ff

My first serious attempt at a user mode TCP/IP stack. It's kind of a superset of some of the above functions. Right now it responds to ICMP pings, sends an RST to all TCP SYNs, and responds to ARP. I'd like it to eventually respond to TCP SYNs and allow session creation, to the point that it will proxy the stdin/stdout over the TCP session, similar to how netcat works.

### Simple "virtual" SYSLOG server
	sudo ./syslogd.py 10.0.0.5 eth0 aa:bb:cc:dd:ee:ff

Essentially the same as usermodeendpoint above, but only displays syslog messages. Will respond to ARP and ping. This is essentially a simple syslog server riding on a usermode ip stack. I think this can be legitmately useful for building a simulated network, or a low overhead service for a multi-container virtual machine or docker environment, or for an application-level controlled hot standby service--it would be easy for one system to run this, and another pings it; if the pings fail, the second one can run its copy which will take over the service nearly seamlessly.

## Windows Support
requires https://github.com/orweis/winpcapy
