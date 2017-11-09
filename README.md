#                                                           Toucan

<p align="center">
  <img width="247" height="209" src="https://github.com/collinsullivanhub/Toucan/blob/master/toucanlogo2.png">
</p>



**"The world is a jungle in general, and the networking game contributes many animals" - RFC 826**
 
Toucan is an IDS written in Python that alerts and defends against several common types of network attacks. For example, "Man in the middle" attacks will be used by hackers to intercept traffic on a network. This is accomplished by sending gratuitous ARPs across a network to "poison" the default gateway and hosts. While ARPs are sent on IPv4 networks to poison targets, IPv6 networks also fall victim to impersonation through gratuitous neighbor advertisements being sent.

If Toucan detects malicious activity, it can respond. For example, if gratuitous ARPs are discovered being sent across a network, Toucan can unpoison the default gateway and the victim, blacklist the attacker's L2, and de-authenticate them from the network.

Toucan uses *accept groups* and *deny groups* to determine which hosts sending traffic are legitimate, or allowed on the network. For example, in a IPv6 RA Flood, one attack association pattern Toucan will use is the fact that many different layer two addresses attached to RAs are being sent accross the network rapidly. Toucan will detect this by checking its accept group to see if that host is allowed on the network, allowed to send router advertisements, will determine that it is not, and will then send a warning.

*I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity*

# Toucan supports both python 2 and 3! 
Use toucan.py for Python 2.7

Use toucan3.py for Python 3.4

*I try to keep them both updated equally, but the python 2 version will likely always be updated with new features before the python 3 version*

# Usage:
- sudo python toucan.py 
- (enter Default Gateway) 200.20.0.1
- (enter network to monitor with netmask in format /X) 200.20.0.0/24
- (enter network interface) wlp2s0/enp5s0/etc (if you do not know this do an 'ifconfig' on linux)

# Video Demo:
https://www.youtube.com/watch?v=EawJJs5iS8A

# Additional Library Requirements

- Pyshark (https://github.com/KimiNewt/pyshark)
- Scapy (https://github.com/secdev/scapy)
- Espeak (http://espeak.sourceforge.net/)

Blue team is the best team, always.
