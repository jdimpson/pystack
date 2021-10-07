# pystack
## Pure Python Usermode IP Stack

Mostly intended as a learning exercise, but secretly also hoping to become a useful utility for unusual network tasks, such as supporting network simulations or clearing TIME_WAIT entries (like https://github.com/rghose/kill-close-wait-connections/blob/master/kill_close_wait_connections.pl). But for now doesn't really do anything but answer pings.

## ALERT
Currently written in Python 2. Conversion to Python 3 is in progress, but since most of this code deals with bytes, strings, and integers, it's basically a rewrite.

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
