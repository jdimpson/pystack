# pystack
## Pure Python 3 Usermode IP Stack

Mostly intended as a learning exercise, but secretly also hoping to become a useful utility for unusual network tasks, such as supporting network simulations, clearing TIME_WAIT entries (like https://github.com/rghose/kill-close-wait-connections/), or an inline deep packet inspector/man-in-the-middler. But for now doesn't really do anything but answer pings. Sometimes.

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

### ICMP ping responder using a TAP device as the interface
	sudo ./tap.py &
	sleep 1
	ping 192.168.7.2

(Doesn't currently respond to pings, but otherwise works great!)

## Windows Support
requires https://github.com/orweis/winpcapy
