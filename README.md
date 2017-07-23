# Toucan

Toucan is currently a monitor to defend against man in the middle attacks (Both IPv4/IPv6 attacks) on a wireless network. For IPv4, when an attacker is discovered sending a gratuitous ARPs, Toucan will send an alert. Additionally, toucan supports IPv6 spoofing defense by monitoring for gratuitous neighbor advertisements (since there is no ARP in IPv6) and also monitors for deauthentication attacks.


*I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity

Blue team best team
