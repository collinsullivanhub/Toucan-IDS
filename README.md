# Toucan

Toucan is an IDS written in Python that alerts and defends against several common types of network attacks. Toucan has the ability to scan for MITM attacks on both IPv4 and IPv6 networks by scanning for gratuitous neighbor advertisements and ARP replies. Toucan will also monitor for deauthentication attacks and router advertisement floods (IPv6). 

If Toucan detects malificent activity, it can respond. For example, if gratuitous ARPs are discovered being sent across a network, Toucan will unpoison the default gateway and unpoison the victim. 

Toucan will also monitor for DNS and MDNS traffic for the situation in which a MITM has occured (and somehow gone unnoticed), any sort of DNS poisoning can be monitored.

*I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity

# Usage:
- sudo python toucan.py
- (enter DG) 192.168.0.1
- (enter network to monitor) 192.168.0.0/24
- (enter interface) wlp2s0

Blue team - Best team
