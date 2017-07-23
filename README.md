# Toucan

Toucan is currently a monitor to defend against man in the middle attacks (Both IPv4/IPv6 attacks) on a network. For IPv4, when an attacker is discovered sending gratuitous ARPs, or gratuitous neighbor advertisements (since ICMPv6 replaced ARP for IPv6 networks), Toucan will alert the admin. Toucan will also scan for deauth attacks against known hosts and detect router advertisement floods (for IPv6).

*I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity

# Usage:
- sudo python toucan.py
- (enter DG) 192.168.0.1
- (enter network to monitor) 192.168.0.0/24
- (enter interface) wlp2s0

Blue team - Best team
