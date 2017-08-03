#-------------------------
# Toucan WIDS 
# Author: Splithor1zon (Collin Sullivan)
# Year: 2017
# Version: 1.0.0
#-------------------------

#--------------------------------------------------------------------------------------------------------------------------------
# Monitors a LAN and will protect against spoofing attacks for MITM purposes
# 1. Scans Network for Active Hosts
# 2. Scans hosts for Layer 2 Addresses and will "attack back" when a MITM is discovered by correcting poisoned hosts
# 3. Will send ALERT 
# Needs to be run as ROOT
#--------------------------------------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------------------------------------
#                    GNU GENERAL PUBLIC LICENSE
#                      Version 3, 29 June 2007

# Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#--------------------------------------------------------------------------------------------------------------------------------


#--------------------------------------------------------------------------------------------------------------------------------

# TO DO:
# 1. Option parser for fast use - but then you don't get to seee my toucan =( 
# 2. Write alert protocol

#--------------------------------------------------------------------------------------------------------------------------------

import logging
import socket, sys
from scapy.all import *
from scapy.error import Scapy_Exception
from scapy.all import sr1,IP,ICMP
from scapy.all import srp
from scapy.all import Ether, ARP, conf
from scapy.all import IPv6
import os
import sys
import threading
from threading import Thread
from optparse import OptionParser
import signal
from struct import *
import time
import pyshark


logging.basicConfig(filename='toucan.log',level=logging.DEBUG)


print "\033[31m'                                                                                                        ............ "
print "\033[31m'                                                                                                ..............-.-----. "
print "\033[31m'                                         .-.                                               ..--.........:---:-------:- "
print "\033[31m'                                           .--                                          .-:-........:-:-:---....``````. "
print "\033[31m'                                            `.-.`````````.-:-.                     .-//:-.....--:::----.. "
print "\033[31m'                                            `..--..`````.-:+:-..-//:.           -+sdmmo-..-.--/::----. "
print "\033[31m'                                            .-///.--:/-.`..-:+///-.:/:.        +hm   h/.--+::-----. "
print "\033[31m'                                            .--/:::-.``-:+-.--/-/+/-----      hmdhssysy/://:::::."
print "\033[31m'                                                    ````....-:---.``.``````+mddhddddmd//+oyds."
print "\033[31m'                                            ..::--...-````....---...```````ommmmddmmmmmsdmmNs"
print "\033[31m'                                            ..-.-:-...``````..-::-:-`.````ommdddmmmmmdddmmmh."
print "\033[31m'                                            ...-::...```````:--:/::```-+hmmddhdmmdyhhhhmmm+`"
print "\033[31m'                                           .---.-:...```````-.-::+--/sdmmdhhhyyddddhhddmmm-"
print "\033[31m'                                            -.`.--...``````.:/oshdddmddddhhyyyssdmdddddmmm."
print "\033[37m'                                                .....````-+ydmmNmmmmddddmmhyyyssosydmdmmmmd."
print "\033[37m'                                                `...```.+hmmmmmmmddddddmNNmhyyyssooosyhdmNNh`"
print "\033[37m'                                                .````.odddddddhdddddmmmNNNmdyyysosoosyyhddh/"
print "\033[37m'                                                   +dmdddddhddddhdddmmNNNmdyyysoossyyhddh+"
print "\033[37m'                                                 -ydddddddddddddmddhdmmdddddhyyyyyyhhddh+"
print "\033[37m'                              ``.`.`            dddddddddddddddhdhydmhhyhmmdhyyyhhddhy:"
print "\033[37m'                                .-:-..`.       dddddhdddddyssyhhyyyyddyhhhmmmmdddddds.```.----...````.-.."
print "\033[37m'                                 .-:+/:..    /dddddhdddho///osyyssssydddddmNNNNNNNms....:::--------.--:-."
print "\033[37m'                                         /:-. :oyhhhhhhs+//:://ossssssyhdmmNNNNNNNd+---://:::----//-----:."
print "\033[37m'                                            +::::++oss/ss+:::-:osysssssydmmNNNmds:-:/++o:-:::.-:--.-...."
print "\033[37m'                                            -yyyo++//+/+/ssy++/--:oossyyyhhdmmhss:...+o+/:::-.---........"
print "\033[37m'                                            ddhyyysysso+ysh:-:::::/+syhhhdhy+-`-:.`.s+/:----.........."
print "\033[37m'                                           +mdhhhyymyhshy+o+/:-.-:///+oss+:.`````::-s/::::+:::-"
print "\033[37m'                                           ymddhyhhdssy+:-:+ys/:..-/+/:---````````.:+/:---/---."
print "\033[34m'                                           ddh+hdmhs+s+----/hhssoo+-://oyyo.````````-//:-:--.."
print "\033[34m'                                           dy+.hmdy+//::-:-ohhyyyoso+::yssy:..````````-/++:-.."
print "\033[34m'                                          :y+.-ydhs+---::.`:ooo++/:/sooh+yy/+::::-----:-+so+::-:-....``.........`"
print "\033[34m'                                          :/:`--/ys+-.-:.````....``.--:/sh+/::::-....-----...........`.-.-.-:```...```.-````--"
print "\033[34m'                                          ./.````ss/---/+-             :o/+o+o++/::::--::--.--..:--//-:-:::--...-.````..````.`"
print "\033[34m'                                                 oy+---::+-            ...-:/-://oooooos+ooo+/+//+//::/:--."
print "\033[34m'                                                 .hs:-:+::+-            ....-.-````````....-..-..---..."
print "\033[34m'                                                  sy://so/:+-"
print "\033[34m'                                                  -h/ososo///.  "
print "\033[34m'                                                   oo+yyo/so/.``````.--...........-----.-.......`"
print "\033[34m'                                                   -s+yyso:+o-```````````````"
print "\033[34m'                                                    osssyoo:/o.               "
print "\033[34m'                                                    :o+osys+:o/                        .....-://oo/---////:.////:.////:."
print "\033[37m'                                                    .s/oyyyo+/o-                        ``..-. TOUCAN INTRUSION DETECTION SYSTEM"
print "\033[34m'                                                     -+/+yho+o++.                            `+o///---////:.////:.////:."
print "\033[34m'                                                     .+/+hhs//s:`                             "
print "\033[34m'                                                      //ohyys:oo`"
print "\033[34m'                                                      .s:ssyys:s:"
print "\033[34m'                                                        //+oyyy+/+"
print "\033[34m'                                                       `-o/oyyo+s+"
print "\033[34m'                                                        /ooshs:/s-  "                             
print "\033[34m'                                                        .o:oyho/oo   "                            
print "\033[34m'                                                        `//oshss+o    "                          
print "\033[34m'                                                         ./+ys++os"
print "\033[34m'                                                          `.+/os++                              The world is a jungle in general, and the"
print "\033[34m'                                                           `-//:-.                               networking game contributes many animals."


os.system("espeak 'Welcome to Toucan IDS'")

class colors:

    Red ='\033[31m'

    Green ='\033[32m'

    Yellow ='\033[33m'

    Blue ='\033[34m'

    Pink ='\033[35m'

    Cyan ='\033[36m'

    White ='\033[37m'

    ENDC = '\033[0m'


time_current = time.strftime("%I:%M:%S")
logging.info('%s' % time_current)
date_current = time.strftime("%d/%m/%Y\n")
logging.info('%s' % date_current)

print colors.Yellow + """
Toucan is a Wireless Intrusion Detection System written in python. Capabilities include scanning and defending hosts
on a network by actively monitoring traffic for several types of known attacks by maleficent users. This program is
not to be used on an unauthorized network and the creator is not responsible for any damage done. Using this program
means you understand and agree to these conditions.
""" + colors.ENDC

print time_current
print date_current

counter = 0
attacker_L2 = ''
attacker_L3 = ''
victim_MAC = ''
victim_L3 = ''
RA_attacker_L3 = ''
RA_attacker_L2 = ''

GATEWAY_IP = raw_input("Enter your Gateway Layer 3 Address: ")
logging.info('Gateway IP: %s' % GATEWAY_IP)

interface = raw_input("\nEnter your Network Interface: ")
logging.info('Interface: %s' % interface)

n_range = raw_input("\nEnter your network range to defend (in format 10.0.0.1/24): ")
logging.info('Network range to defend: %s' % n_range)

print colors.Red + "[*] Gateway Locked in..." 
time.sleep(.2)
print "[*] Interface configured..."
time.sleep(.2)
print"[*] Network Range set..."
time.sleep(.2)
print"[*] Commensing..." + colors.ENDC
print"\n"


def get_mac_gateway(ip_address):

    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=2)

    for s, r in response:
        return r[Ether].src
    return None

    logging.info('Gateway Layer 2 address is: %s' % r[Ether].src)

    GATEWAY_MAC = "%s" % r[Ether].src


def arp_network_range(iprange="%s" % n_range):

    logging.info('Sending ARPs to network range %s' % n_range)

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange), timeout=5)

    collection = []

    for snd, rcv in ans:

        result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()

        logging.info('%s' % result)
        
        collection.append(result)

    for host in collection:

        print host

 
def arp_display(packet):

    if packet[ARP].op == 1: 

        logging.info('[*] Probe- %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst))

        return '\033[31m[*] Probe- %s is asking for L2 of %s\033[0m' % (packet[ARP].psrc, packet[ARP].pdst)

    if packet[ARP].op == 2: 

        logging.info('[*] Response- %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc))

        return '\033[33m[*] Response- %s L3 address is %s\033[0m' % (packet[ARP].hwsrc, packet[ARP].psrc)


def arp_display_2(packet):

  if packet[ARP].op == 1 and packet[ARP].psrc != GATEWAY_IP and packet[ARP].hwsrc == GATEWAY_MAC:

      print "\033[31m[*]WARNING: GATEWAY IMPERSONTATION DETECTED. POSSIBLE MITM ATTACK FROM %s\033[31m" % (packet[ARP].psrc)

  if packet[ARP].op == 2 and packet[ARP].psrc != GATEWAY_IP and packet[Ether].src == GATEWAY_MAC:

      print "\033[31m[*]WARNING: GATEWAY IMPERSONTATION DETECTED. POSSIBLE MITM ATTACK FROM %s\033[31m" % (packet[ARP].psrc)

      

def na_packet_discovery(neighbor_adv_packet):

  if neighbor_adv_packet.haslayer(IPv6) and neighbor_adv_packet.haslayer(ICMPv6ND_NA):

    print "[*]Neighbor advertisement discovered: %s" % (neighbor_adv_packet.summary())

    print '[*]Neighbor advertisement source: %s, destination: %s ' % (neighbor_adv_packet[IPv6].src, neighbor_adv_packet[IPv6].dst)  

    logging.info('Neighbor advertisement source: %s, destination: %s' % (neighbor_adv_packet[IPv6].src, neighbor_adv_packet[IPv6].dst))


def ns_packet_discovery(neighbor_sol_packet):

  if neighbor_sol_packet.haslayer(IPv6) and neighbor_sol_packet.haslayer(ICMPv6ND_NS):

    print "\033[32m[*]Neighbor solicitation discovered: %s\033[0m" % (neighbor_sol_packet.summary())

    print '\033[32m[*]Neighbor solicitation source: %s, destination: %s\033[0m' % (neighbor_sol_packet[IPv6].src, neighbor_sol_packet[IPv6].dst)  

    logging.info('Neighbor solicitation source: %s, destination: %s' % (neighbor_sol_packet[IPv6].src, neighbor_sol_packet[IPv6].dst))



def detect_deauth(deauth_packet):

  if deauth_packet.haslayer(Dot11) and deauth_packet.type == 0 and deauth_packet.subtype == 0xC:

    print "DEAUTH DETECTED: %s" % (deauth_packet.summary())

    print "Deauthentication Detected from: %s" % (deauth_packet[IPv4].psrc, deauth_packet[Ether].hwsrc)

    logging.warning('Deauth detected')

    logging.warning('Responding to deauthentication.')


def detect_router_advertisement_flood(ra_packet):

  if ra_packet.haslayer(IPv6) and ra_packet.haslayer(ICMPv6ND_RA):

    print "\033[32m[*]Router advertisement discovered: %s\033[0m" % (ra_packet.summary())

    print '[*]Router advertisement discovered from %s with L2 address of ' % (ra_packet[IPv6].src, ra_packet[ICMPv6ND_RA].src_ll_addr)

    logging.info('RA from %s' % (ra_packet[IPv6].src))


def defenseive_arps(GATEWAY_IP, GATEWAY_MAC, victim_L3, victim_MAC):

    un_poison_victim = ARP()

    un_poison_victim.op = 2

    un_poison_victim.psrc = gateway_ip

    un_poison_victim.pdst = victim_L3

    un_poison_victim.hwsrc = GATEWAY_MAC

    un_poison_gateway = ARP()

    un_poison_gateway.op = 2

    un_poison_gateway.psrc = victim_L3

    un_poison_gateway.pdst = gateway_ip

    un_poison_gateway.hwsrc = victim_MAC

    send(un_poison_victim)
    
    send(un_poison_gateway)

    time.sleep(2)


def defensive_deauth(GATEWAY_MAC, attacker_L2):

  conf.iface = interface
  
  bssid = GATEWAY_MAC 

  count = 77

  conf.verb = 0 

  packet = RadioTap()/Dot11(type=0,subtype=12,addr1=attacker_L2,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7) 

  logging.info('Intruder at %s is being kicked off network' % attacker_L2)

  for n in range(int(count)):

    sendp(packet)

    print '\033[32mRemoving malicious host at with Layer 2 address:' + attacker_L2 + 'off of network.\033[0m'

 
def print_dns_info(pkt):

    if pkt.dns.qry_name:

        print '\033[35mDNS Request from %s to %s\033[35m' % (pkt.ip.src, pkt.dns.qry_name)

    elif pkt.dns.resp_name:

        print '\033[35mDNS Response from %s to %s\033[0m' % (pkt.ip.src, pkt.ip.dst)


def print_mdns_info(pkt):

  print '\033[35mMDNS Request from %s to %s\033[0m' % (pkt.src, pkt.dst)


def sniff_mdns():

  cap = pyshark.LiveCapture(interface='%s' % interface, bpf_filter='udp port 5353')
   
  cap.sniff(packet_count=10)  

  cap.apply_on_packets(print_mdns_info)


def sniff_dns():

  cap = pyshark.LiveCapture(interface='%s' % interface, bpf_filter='udp port 53')
   
  cap.sniff(packet_count=10)  

  cap.apply_on_packets(print_dns_info)


def sniff_arps():

  sniff(filter = "arp", prn = arp_display)


def sniff_arps_2():

  sniff(filter = "arp", prn = arp_display_2)


def sniff_deauth():

  sniff(iface="%s" % interface, prn = detect_deauth)


def sniff_ns():

  sniff(iface="%s" % interface, prn = ns_packet_discovery) 


def sniff_na():

  sniff(iface="%s" % interface, prn = na_packet_discovery)


def sniff_ra():

  sniff(iface="%s" % interface, prn = detect_router_advertisement_flood)


if __name__ == '__main__':

    GATEWAY_MAC = get_mac_gateway(GATEWAY_IP)

    print colors.Red + "[*] Gateway %s is at %s" % (GATEWAY_IP, GATEWAY_MAC) + colors.ENDC

    arp_network_range()

    Thread(target = sniff_arps).start()

    Thread(target = sniff_arps_2).start()

    Thread(target = sniff_deauth).start()

    Thread(target = sniff_ns).start()

    Thread(target = sniff_na).start()

    Thread(target = sniff_ra).start()

    Thread(target = sniff_dns).start()

    Thread(target = sniff_mdns).start()
 
