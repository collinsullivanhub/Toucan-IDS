# Toucan

Toucan is an IDS written in Python that alerts and defends against several common types of network attacks. For example, "Man in the middle" attacks will be used by any hacker worth their salt to intercept traffic on a network. This is accomplished by sending gratuitous ARPs across a network to "poison" the default gateway and hosts. While ARPs are sent on IPv4 networks to poison targets, IPv6 networks also fall victim to impersonation through gratuitous neighbor advertisements being sent.

If Toucan detects maleficent activity, it can respond. For example, if gratuitous ARPs or Neighbor Adervisements are discovered being sent across a network, Toucan will unpoison the default gateway and the victim, blacklist the attacker's L2 and deauth them from the network.

Toucan will also defend against:
-Deauthentication attacks
-Router Advertisement floods (IPv6)


*I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity

# Usage:
- sudo python toucan.py 
- (enter Default Gateway) 192.168.0.1
- (enter network to monitor) 192.168.0.0/24
- (enter interface) wlp2s0

Libs:

-Scapy
-Pyshark

Blue team is the best team, always
