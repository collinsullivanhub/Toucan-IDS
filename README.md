# Toucan

The world is a jungle in general, and the networking game contributes many animals" - RFC 826
 
Toucan is an IDS written in Python that alerts and defends against several common types of network attacks. For example, "Man in the middle" attacks will be used by any hacker worth their salt to intercept traffic on a network. This is accomplished by sending gratuitous ARPs across a network to "poison" the default gateway and hosts. While ARPs are sent on IPv4 networks to poison targets, IPv6 networks also fall victim to impersonation through gratuitous neighbor advertisements being sent.

If Toucan detects maleficent activity, it can respond. For example, if gratuitous ARPs are discovered being sent across a network, Toucan can unpoison the default gateway and the victim, blacklist the attacker's L2 and deauth them from the network.


*I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity

# Toucan supports both python 2 and 3! 
Use toucan.py for Python 2.7

Use toucan3.py for Python 3.4

**I try to keep them both updated equally, but the python 2 version will likely always be more updated**

# Usage:
- sudo python toucan.py 
- (enter Default Gateway) 192.168.0.1
- (enter network to monitor) 192.168.0.0/24
- (enter interface) wlp2s0

# Video Demo:
https://www.youtube.com/watch?v=EawJJs5iS8A

# Additional Library Requirements

- Pyshark (https://github.com/KimiNewt/pyshark)
- Scapy (https://github.com/secdev/scapy)
- Espeak (http://espeak.sourceforge.net/)

Blue team is the best team, always.
